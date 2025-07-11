#!/usr/bin/env python3

"""
Juniper EX Upgrade Utility

This script prepares Juniper EX switches (standalone or virtual chassis) for a software upgrade.
It automates cleanup (logs, snapshots), migrates deprecated configuration, and performs a versioned upgrade based on Netbox SOT.
All device operations are performed via Juniper PyEZ and SSH/paramiko automation.
Designed for operational reliability and clarity, with status-coloring for all major steps.
"""

import argparse
import getpass
import jcs
import requests
import sys
import time
import urllib3

from jnpr.junos import Device
from jnpr.junos.utils.config import Config
from jnpr.junos.utils.start_shell import StartShell
from jnpr.junos.utils.sw import SW
from lxml import etree
from jnpr.junos.exception import RPCError
import pexpect

# Suppress the InsecureRequestWarning
# Suppress the InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


import paramiko

# ANSI color escape codes for status output
_STATUS_COLORS = {
    "INFO": "\033[36m",      # Cyan
    "SUCCESS": "\033[32m",   # Green
    "WARNING": "\033[33m",   # Yellow
    "ERROR": "\033[31m",     # Red
}
_STATUS_RESET = "\033[0m"

def print_status(message, level="INFO", file=sys.stdout):
    """
    Utility function to print status messages with color for visibility.

    Args:
        message (str): The message to print.
        level (str): One of "INFO", "SUCCESS", "WARNING", "ERROR".
        file: Where to print (default: stdout).
    """
    color = _STATUS_COLORS.get(level, "")
    reset = _STATUS_RESET if color else ""
    print(f"{color}[{level}] {message}{reset}", file=file)

def mount_oam_volume_via_ssh(host, user, ssh_password, root_password, timeout=30):
    """
    SSH to a Junos device, escalate to root shell using `start shell user root`, and mount /dev/gpt/oam/ as /oam/.

    Automates password prompts, shell prompt detection, and permission fixing for OAM access.
    Used for copying firmware and helper packages before upgrades.

    Args:
        host (str): Device hostname or IP.
        user (str): Username for login.
        ssh_password (str): SSH login password for user.
        root_password (str): Root account password for privilege escalation.
        timeout (int): How long to wait for prompts/commands.

    Returns:
        None
    """
    import sys
    import time

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print_status("Mounting /dev/gpt/oam/ to /oam/ and setting permissions in root shell", "INFO")
        client.connect(host, username=user, password=ssh_password, timeout=timeout)
        chan = client.invoke_shell()
        chan.settimeout(timeout)

        # Helper: Wait for any prompt in list of expected prompts, returns buffer.
        def expect(chan, prompts, timeout=30):
            """
            Waits for any prompt in 'prompts' list, returns text up to and including prompt.
            """
            import time
            buf = ""
            start_time = time.time()
            while True:
                if chan.recv_ready():
                    data = chan.recv(4096).decode("utf-8")
                    buf += data
                    for p in prompts:
                        if p in buf:
                            return buf
                if time.time() - start_time > timeout:
                    raise TimeoutError(f"Timeout waiting for prompt(s): {prompts}")
                time.sleep(0.1)

        # Step 1: Wait for initial device CLI prompt.
        expect(chan, [">\n", "> ", "#\n", "# "], timeout=timeout)

        # Step 2: Escalate to root shell.
        chan.send("start shell user root\n")
        output = expect(chan, ["Password:", "password:"], timeout=timeout)
        if "Password" in output or "password" in output:
            chan.send(root_password + "\n")
            # Step 3: Escalation successful, wait for root shell prompt.
            expect(chan, ["#", "$", "%"], timeout=timeout)
            # Step 4: Mount OAM and fix permissions.
            chan.send("mount /dev/gpt/oam/ /oam/\n")
            expect(chan, ["#", "$", "%"], timeout=timeout)
            chan.send("chmod -R 777 /oam/\n")
            expect(chan, ["#", "$", "%"], timeout=timeout)
            print_status("Mounted /dev/gpt/oam/ to /oam/ and set permissions in root shell.", "SUCCESS")
        else:
            print_status("Did not get password prompt for 'start shell user root'; cannot proceed.", "ERROR")

        chan.close()
    except Exception as e:
        print_status(f"Paramiko automation failed (junos-cli mode): {e}", "ERROR", file=sys.stderr)
        sys.exit(1)
    finally:
        client.close()

def myprogress(dev, report):
    """
    Progress callback for SW.install() operations.
    Logs software installation progress to stdout and syslog.
    Args:
        dev (Device): Junos Device instance.
        report (str): Installation progress status.
    """
    print_status(f"host: {dev.hostname}, report: {report}", "INFO")

def count_vchassis_members(dev, hostname):
    """
    Check and report on Juniper Virtual Chassis (VC) members' presence for upgrade safety.

    Args:
        dev (Device): PyEZ device object.
        hostname (str): Device name for logging.

    Returns:
        member_ids (list of str): List of VC member IDs. Exits the script if any are not present.
    """
    print_status(f"Determining Virtual Chassis Members on {hostname}", "INFO")
    vchassis_xml = dev.rpc.get_virtual_chassis_information()
    members = vchassis_xml.findall(".//member")
    member_statuses = []
    member_ids = []
    for m in members:
        mid = m.findtext("member-id")
        status = m.findtext("member-status")
        if mid is not None:
            member_ids.append(mid)
        member_statuses.append((mid, status))
    # If standalone, just note and move on.
    if member_ids:
        if len(member_ids) == 1:
            print_status(f"Device is a standalone switch: {hostname}", "INFO")
        else:
            max_member = max(int(mid) for mid in member_ids)
            total_members = max_member + 1
            print_status(f"Total VC members on {hostname}: {total_members}", "INFO")
    else:
        print_status("No VC members found!", "ERROR")
        sys.exit(1)
    # If any member is not "prsnt", abort the upgrade for safety.
    not_prsnt = []
    for mid, status in member_statuses:
        if status and status.lower() != "prsnt":
            not_prsnt.append((mid, status))
    if not_prsnt:
        print_status("Members with non-'Present' status:", "WARNING")
        for mid, status in not_prsnt:
            print(f"    Member {mid} status: {status}")  # Not colored, content only
        print_status("ABORTING: One or more VC members are not Present.", "ERROR")
        sys.exit(1)
    return member_ids

def delete_remote_file(dev, target_path):
    """
    Utility for deleting files or directories on the device via RPC.
    Used for cleaning logs and snapshots.

    Args:
        dev: PyEZ device object.
        target_path (str): Path to delete (may be wildcards).
    """
    rpc = etree.Element("file-delete")
    path = etree.SubElement(rpc, "path")
    path.text = target_path
    try:
        rsp = dev.execute(rpc)
        print_status(f"Deleted logs on {target_path}", "SUCCESS")
    except Exception as e:
        print_status(f"Failed deleting files at {target_path}: {e}", "ERROR")
        sys.exit(1)

def repd_and_snapshot_cleanup(dev, member_ids, hostname, model):
    """
    Cleans up repd logs, schema-cache, and snapshots on all applicable VC members or standalone switches.

    For EX4300:
        - Handles .schema-cache cleanup per FPC using delete_remote_file API.
    For all models:
        - Triggers system storage cleanup and snapshot deletion via CLI.

    Args:
        dev: Device
        member_ids: List of member IDs (str)
        hostname: Device name/host
        model: Device model string

    Exits if anything fails.
    """
    if "EX4300" in model:
        if len(member_ids) == 1:
            target = "/var/tmp/.schema-cache/*"
            print_status(f"Deleting schema-cache on {target} ...", "INFO")
            delete_remote_file(dev, target)
        else:
            for member_id in member_ids:
                target = f"fpc{member_id}:/var/tmp/.schema-cache/*"
                print_status(f"Deleting schema-cache on {target} ...", "INFO")
                delete_remote_file(dev, target)
    if len(member_ids) == 1:
        print_status(f"Cleaning up switch {hostname}", "INFO")
        target = "/var/log/shmlog/repd/*"
        if "EX4300" not in model:
            print_status(f"Deleting logs on switch {hostname} at {target} ...", "INFO")
            delete_remote_file(dev, target)
            # Delete /oam/snapshot/recovery.ufs.uzip
            delete_remote_file(dev, "/oam/snapshot/recovery.ufs.uzip")
        try:
            dev.rpc.cli("request system snapshot delete *")
            print_status(f"Requested snapshot delete on switch {hostname}", "INFO")
            dev.rpc.cli("request system snapshot recovery delete *")
            print_status(f"Requested snapshot delete recovery on switch {hostname}", "INFO")
        except Exception as e:
            print_status(f"Snapshot cleanup failed for switch {hostname}", "ERROR")
            sys.exit(1)
    else:
        if "EX4300" not in model:
            print_status(f"Cleaning up VC Members on {hostname}", "INFO")
            for member_id in member_ids:
                print_status(f"Cleanup on member {member_id}", "INFO")
                target = f"fpc{member_id}:/var/log/shmlog/repd/*"
                if "EX4300" not in model:
                    print_status(f"Deleting logs on {target} ...", "INFO")
                    delete_remote_file(dev, target)
                    # Delete /oam/snapshot/recovery.ufs.uzip
                    delete_remote_file(dev, "/oam/snapshot/recovery.ufs.uzip")
                try:
                    dev.rpc.cli(f"request system snapshot delete * member {member_id}")
                    print_status(f"Requested snapshot delete on member {member_id}", "INFO")
                    dev.rpc.cli(f"request system snapshot recovery delete * member {member_id}")
                    print_status(f"Requested snapshot delete recovery on switch {member_id}", "INFO")
                except Exception as e:
                    print_status(f"Snapshot cleanup failed for member {member_id}:", "ERROR")
                    sys.exit(1)
    # Run system storage cleanup ONCE for all members after all snapshot deletes
    try:
        if len(member_ids) == 1:
            print_status(f"Requested storage cleanup for switch {hostname}", "INFO")
        else:
            print_status(f"Requested storage cleanup for all VC members on {hostname}", "INFO")
        rpc = etree.Element("request-system-storage-cleanup")
        dev.execute(rpc)
        with StartShell(dev) as shell:
            print_status(f"Cleaning Up Old Artifacts on {hostname}", "INFO")
            shell.run('pkg setop rm previous')
            shell.run('pkg delete old')
        print_status("Cleanup Completed", "SUCCESS")
    except Exception as e:
        print_status(f"Storage cleanup failed: {e}", "ERROR")
        sys.exit(1)

def gigether_migration_config_lines(dev):
    """
    Builds configuration lines for migrating deprecated 'gigether-options' to 'ether-options'.

    Returns:
        List of config lines, combining delete/set for migrations.
    """
    import re
    try:
        config = dev.rpc.get_config(options={"format": "set"}, timeout="120")
        config_text = config.text
        if not config_text or not isinstance(config_text, str):
            print_status("No configuration retrieved or config_text is not a valid string. Aborting migration line generation.", "ERROR")
            return []

        # Parse config_text strictly by line breaks, ignoring block concatenation
        # Accept only lines starting with "set " (following optional whitespace)
        lines = config_text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        set_lines = []
        for line in lines:
            line = line.strip()
            # Skip empty/non-set lines
            if not line or not line.lower().startswith("set "):
                continue
            # If line contains additional "set " embedded (concatenated), split further
            parts = re.split(r"(?= set )", line)
            for part in parts:
                part = part.strip()
                if part.lower().startswith("set "):
                    set_lines.append(part)

        changes = []
        matched = 0
        for line in set_lines:
            if "gigether-options" in line.lower():
                matched += 1
                delete_line = re.sub(r"(?i)^set", "delete", line, count=1)
                set_line = re.sub(r"(?i)gigether-options", "ether-options", line)
                changes.append(delete_line)
                changes.append(set_line)

        return changes
    except Exception as e:
        print_status(f"Error while building gigether migration config lines: {e}", "ERROR")
        sys.exit(1)
        return []

def apply_gigether_migration_config(dev, check_mode, commit_mode, changes, hostname) -> None:
    """
    Loads candidate config for gigether migration and either checks or commits, showing diffs.

    Args:
        dev: PyEZ device object.
        check_mode: If True, do not commit, only check.
        commit_mode: If True, commit the candidate configuration.
        changes: List of migration config lines.
        hostname: Device name for logging.
    """
    if not changes:
        print_status(f"No config changes needed on {hostname} (no gigether migration lines generated).", "INFO")
        return
    print_status("The Following Config Has Been Generated:", "INFO")
    for line in changes:
        print(line)

    try:
        cu = Config(dev)
        cu.lock()
        print_status("Config candidate locked. Loading migration lines...", "INFO")
        cu.load("\n".join(changes), format="set", merge=True)
        print_status("Candidate Config Diff With Proposed Changes:", "INFO")
        diff_str = cu.diff()

        def format_junos_diff(diff):
            import re
            # Split diff into blocks, each begins with "[edit"
            blocks = re.split(r"(\[edit[^\]]+\])", diff)
            output = []
            i = 0
            while i < len(blocks):
                block = blocks[i]
                if not block.strip():
                    i += 1
                    continue
                if block.startswith("[edit"):
                    output.append(block.strip())
                    # The changes for this block are in the next element, unless at the end
                    if i + 1 < len(blocks):
                        block_body = blocks[i + 1]
                        # Tokenize changes: break so that every "+ ... {", "- ... }", "+ ... ;", etc. is on its own line
                        # Insert newline before each + or - (if not already at a line start)
                        lines = re.split(r"(?=[+-] )", block_body.strip())
                        # Each line may contain multiple statements (e.g., "+ foo { + bar; }")
                        # Further break up each line on "{", "}", and ";", while keeping +/-
                        l2 = []
                        for line in lines:
                            # only non-empty
                            line = line.strip()
                            if not line:
                                continue
                            # Find all tokens: + something {, + something ;, - something }, etc.
                            # Split on "{", "}", and ";", keeping tokens
                            tokens = re.findall(r"([+-] [^{};]+[;{}]|[+-] [^{};]+)", line)
                            if not tokens:
                                tokens = [line]
                            l2.extend(tokens)
                        # Now, for each token, build indentation
                        indent = 0
                        for token in l2:
                            t = token.strip()
                            is_plus = t.startswith("+")
                            is_minus = t.startswith("-")
                            # Remove initial +/- and space for indent logic
                            t_stripped = t[2:].strip() if (is_plus or is_minus) else t.strip()
                            if t_stripped == "}":
                                indent -= 1
                            pad = "    " * indent
                            outl = ""
                            if is_plus:
                                outl = "+" + pad + t[1:].rstrip()
                            elif is_minus:
                                outl = "-" + pad + t[1:].rstrip()
                            else:
                                outl = pad + t.rstrip()
                            output.append(outl)
                            if t_stripped == "{":
                                indent += 1
                    i += 2
                else:
                    i += 1
            return "\n".join(output) + "\n"

        print(format_junos_diff(diff_str))
        if commit_mode:
            print_status("Committing candidate configuration with Commit Confirm of 2 Minutes", "INFO")
            commit_comment = "Automated Gigether Migration"
            cu.commit(comment=commit_comment, timeout=120, confirm=2)
            print_status(f"Waiting 30 seconds to verify {hostname} is still reachable", "INFO")
            time.sleep(30)
            print_status("Performing Final Commit", "INFO")
            cu.commit()
        elif check_mode:
            print_status("Performing commit check", "INFO")
            cu.commit_check(timeout=120)
            print_status("Commit check complete", "SUCCESS")
        cu.unlock()
        print_status("Config candidate unlocked.", "SUCCESS")
    except Exception as e:
        print_status(f"Error loading or committing gigether migration config: {e}", "ERROR")
        sys.exit(1)
def parse_args_and_credentials():
    """
    Parse CLI arguments for host, user, password, and operational mode.

    Prompts for passwords if not given. Returns a tuple (args, password, root_password).
    """
    parser = argparse.ArgumentParser(description="Combined Junos VC check, cleanup, and gigether config migration tool.")
    parser.add_argument("--host", required=True, help="Hostname or IP of the Junos device")
    parser.add_argument("--user", required=True, help="Login username")
    parser.add_argument("--password", help="Login password (if not provided, will prompt)")
    parser.add_argument("--root-password", help="Root password for privileged operations (if not provided, will prompt)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help='Print only lines from config containing "gigether" and exit')
    group.add_argument("--commit", action="store_true", help="Generate, load, and commit gigether migration config")
    parser.add_argument("--no-cleanup", action="store_true", help="Bypass cleanup of repd logs and snapshots")
    args = parser.parse_args()
    if not args.check and not args.commit:
        args.check = True
    password = args.password if args.password else getpass.getpass(prompt="Password: ")
    root_password = args.root_password if args.root_password else getpass.getpass(prompt="Root Password: ")
    return args, password, root_password

def connect_and_mount_oam(args, password, root_password):
    """
    Thin wrapper to mount OAM volume before any config/upgrade logic.
    Assumes model has already been checked.
    """
    print_status(f"Connecting to device {args.host} as {args.user} for OAM mount.", "INFO")
    mount_oam_volume_via_ssh(args.host, args.user, password, root_password)

def get_device_facts(args, password):
    """
    Opens a Junos device session, retrieves and returns the .facts dictionary, then closes the device.

    Args:
        args: Parsed argparse object.
        password: Device admin password.

    Returns:
        Junos device .facts dict.
    """
    dev = Device(host=args.host, user=args.user, passwd=password, normalize=True)
    dev.open()
    dev.timeout = 300
    facts = dev.facts
    dev.close()
    return facts

def cleanup_logs_and_snapshots(dev, member_ids, hostname, model, skip_cleanup):
    """
    Controls whether to perform full repd/snapshot cleanup or skip it,
    and logs accordingly.
    """
    if not skip_cleanup:
        repd_and_snapshot_cleanup(dev, member_ids, hostname, model)
    else:
        print_status("Skipping cleanup phase (--no-cleanup specified)", "INFO")
        jcs.syslog("interact.notice", "Just testing")

def migrate_gigether_configs(dev, check_mode, commit_mode, hostname):
    """
    Gathers config changes and applies (or checks) the gigether migration,
    as appropriate for operational mode.
    """
    changes = gigether_migration_config_lines(dev)
    apply_gigether_migration_config(dev, check_mode, commit_mode, changes, hostname)

def netbox_lookup_and_validation(serialnumber, model):
    """
    Query Netbox by serial number, validate device model, and extract
    target software version, package name, and relevant flags.

    Returns:
        (target_version, pkg, vmhost, force_host) tuple
    """
    url = "https://<your-netbox>/api/dcim/devices"
    find_serial_url = f"{url}/?serial={serialnumber}"
    nb_token = "<your-netbox-token>"
    headers = {"Authorization": f"Token {nb_token}"}
    print_status(f"Searching for Device in Netbox using Serial Number: {serialnumber}", "INFO")
    try:
        nb_device_response = requests.get(find_serial_url, headers=headers, verify=False)
    except requests.exceptions.RequestException as e:
        print_status(f"Error making Netbox request: {e}", "ERROR")
        sys.exit()
    response_json = nb_device_response.json()
    results = response_json.get("results", [])
    if results:
        first_result = results[0]
        device_model = first_result.get("device_type", {}).get("model")
    else:
        print_status("No device found. Verify that this device's serial number is in Netbox.", "ERROR")
        sys.exit(1)
    if model != device_model:
        print_status(f"Device model in Netbox ({device_model}) does not match this device ({model}).", "ERROR")
        sys.exit(1)
    target_version, pkg, vmhost, force_host = None, None, False, False
    for entry in results:
        config_context = entry.get("config_context", {})
        pkg = config_context.get("pkg")
        target_version = config_context.get("target_version")
        if config_context.get("vmhost"):
            vmhost = True
        if config_context.get("force_host"):
            force_host = True
        if pkg and target_version:
            pkg = pkg.replace("{target_version}", target_version)
            print_status(f"Located Target Version for this model: {target_version}", "INFO")
        else:
            print_status("No Target Version for this model found", "ERROR")
            sys.exit(1)
    return target_version, pkg, vmhost, force_host

def perform_software_upgrade(args, password, model, version, target_version, pkg):
    """
    Performs the versioned software upgrade workflow:
    - Installs helper/OS packages (EX2300/3400 only)
    - Downloads the .tgz image if required
    - Installs upgrade package
    - Deletes helper packages post-upgrade (EX2300/3400 only)
    - Exits if successful

    Args:
        args: Command-line arguments from argparse
        password: Device login password
        model, version, target_version, pkg: Device/software details
    """
    pkg_filename = pkg.split('/')[-1]
    pkg_url = f"http://<your-file-repo>/juniper/firmware/{pkg}"
    new_pkg = f"/.mount/oam/{pkg_filename}"
    print_status(f"Device needs to be upgraded to {target_version}", "INFO")
    with Device(host=args.host, user=args.user, passwd=password, normalize=True) as dev:
        sw = SW(dev)
        dev.timeout=300
        print_status("Rolling Back Any Pending Installs", "INFO")
        rollback_rpc = etree.Element("request-package-rollback")
        dev.execute(rollback_rpc)
        # Only for non-EX4300: install helper packages
        if "EX4300" not in model:
            print_status("Installing Helper Packages", "INFO")
            try:
                print_status("Installing OS Package", "INFO")
                ok = sw.pkgadd(remote_package="http://<your-file-repo>/juniper/firmware/ex3400/os-package.tgz")
            except Exception as err:
                print_status(f"Error installing OS package: {err}", "ERROR")
                ok = False
            try:
                print_status("Installing Package Hooks", "INFO")
                ok = sw.pkgadd(remote_package="http://<your-file-repo>/juniper/firmware/ex3400/package-hooks-ex.tgz")
            except Exception as err:
                print_status(f"Error installing package hooks: {err}", "ERROR")
                ok = False
            print_status("Helper Packages Install Complete", "SUCCESS")
        try:
            if "EX4300" not in model:
                print_status(f"Downloading {target_version} from {pkg_url} to /.mount/oam", "INFO")
                dev.rpc.file_copy(source=pkg_url, destination="/.mount/oam", dev_timeout=1800)
                print_status(f"Installing {target_version} for {model}", "INFO")
                ok, msg = sw.pkgadd(remote_package=new_pkg, unlink=True, force=True, dev_timeout=2100)
                print_status(f"Install Complete: {msg}", "SUCCESS")
            else:
                print_status(f"Installing {target_version} for {model}", "INFO")
                ok, msg = sw.install(package=pkg_url, unlink=True )
                print_status(f"Install Complete: {msg}", "SUCCESS")
        except Exception as err:
            print_status(f"Error installing software: {err}", "ERROR")
            ok = False
        except RPCError as err:
            print_status(f"Error installing software (RPC): {err}", "ERROR")
            ok = False
        if ok is True:
            # Only for non-EX4300: remove helper packages
            if "EX4300" not in model:
                print_status("Removing Helper Packages", "INFO")
                try:
                    dev.rpc.cli("request system software delete os-package")
                    print_status("Deleted os-package after install.", "INFO")
                except Exception as e:
                    print_status(f"Failed to delete os-package: {e}", "ERROR")
                    sys.exit(1)
                try:
                    dev.rpc.cli("request system software delete package-hooks-platform")
                    print_status("Deleted package-hooks-platform after install.", "INFO")
                except Exception as e:
                    print_status(f"Failed to delete package-hooks-platform: {e}", "ERROR")
                    sys.exit(1)
                print_status("Helper Packages Removed. Ready to reboot during scheduled window.", "SUCCESS")
        else:
            print_status(f"Unable to install software: {msg}", "ERROR")
            sys.exit(1)

def main():
    """
    Main script orchestration:
    - Parse arguments and credentials
    - Optionally mount OAM if model is not EX4300
    - Connect to device, check VC state
    - Perform cleanup (unless --no-cleanup)
    - Migrate gigether configs
    - Query Netbox for target software
    - If upgrade needed: perform software install and helper install/removal
    """
    args, password, root_password = parse_args_and_credentials()

    # Open device once to get facts/model info, then re-use connection logic below
    with Device(host=args.host, user=args.user, passwd=password, normalize=True) as dev:
        dev.timeout = 300
        facts = dev.facts
        model = facts.get("model", args.host)
        version = facts.get("versions", args.host)
        hostname = facts.get("hostname", args.host)
        serialnumber = facts.get("serialnumber", args.host)

    # Only mount OAM if model is NOT EX4300
    if "EX4300" not in model:
        connect_and_mount_oam(args, password, root_password)
    else:
        print_status(f"Skipping OAM mount: Not Needed On {model}", "INFO")

    try:
        check_mode = bool(args.check)
        commit_mode = bool(args.commit)
        # Open device session
        with Device(host=args.host, user=args.user, passwd=password, normalize=True) as dev:
            dev.timeout = 300
            # Use model, version, hostname, serialnumber already determined above
            member_ids = count_vchassis_members(dev, hostname)
            # --- Cleanup logs/snapshots unless --no-cleanup ---
            cleanup_logs_and_snapshots(dev, member_ids, hostname, model, args.no_cleanup)
            # --- GIGETHER migration workflow ---
            migrate_gigether_configs(dev, check_mode, commit_mode, hostname)
        # --- Query Netbox for version/package assignment ---
        target_version, pkg, vmhost, force_host = netbox_lookup_and_validation(serialnumber, model)
        # --- Upgrade if device version does not match Netbox assignment ---
        if version != target_version:
            perform_software_upgrade(args, password, model, version, target_version, pkg)
        else:
            print_status(f"Device is already running version {version}", "INFO")
    except Exception as e:
        print_status(f"Device connection or RPC error: {e}", "ERROR", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    # Entry point: run main orchestration
    main()
