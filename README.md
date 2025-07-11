# Juniper EX Upgrade Utility

This utility script provides a seamless workflow for preparing Juniper EX switches (standalone or virtual chassis) for software upgrades. It automates the following:

- Checks that all Virtual Chassis (VC) members are present and reachable.
- Cleans up repd logs and old system snapshots on all members to free space and prepare for upgrade.
- Migrates deprecated `gigether-options` configuration to `ether-options`, as required in recent Junos releases.
- Automatically discovers and upgrades to the correct Junos firmware version using Netbox as a source of truth for target version and software package, including downloading and installing the firmware image if required.
- Installs and removes required helper packages before and after upgrade as needed.
- Offers dry-run (preview/check) and commit (apply) operational modes.
- Supports bypassing the cleanup stage if required (see `--no-cleanup`).

## Features

- **Virtual Chassis Awareness:** Automatically discovers VC membership and ensures all are present before upgrade.
- **Automated Cleanup:** Deletes unnecessary logs and snapshots across all VC members using robust RPC and CLI automation.
- **GigEther Migration Automation:** Finds and safely migrates all `gigether-options` config lines, including a dry-run preview and diff.
- **Modular, Reliable Execution:** Each operational phase (VC check, cleanup, migration, upgrade, etc.) is handled by a dedicated, well-named function—see below for more on workflow structure.
- **Safe Operations:** Offers a default dry-run mode for safe review of all changes before committing.
- **Automatic Versioned Upgrade:** Locates the desired software version and package for the target device from Netbox, and installs it if an upgrade is required.
- **Helper Package Support:** Pre-loads and cleans up required helper OS and platform packages during any upgrade. See KB31198(https://supportportal.juniper.net/s/article/EX-Not-enough-storage-while-upgrading-Junos-EX2300-and-EX3400)
- **OAM Access via SSH (non-EX4300 models only):** Automates mounting of the OAM filesystem using root privileges via SSH for EX2300/3400 (not EX4300 series), including password prompting and fallbacks. See KB31201(https://supportportal.juniper.net/s/article/EX-Upgrading-Junos-on-EX2300-and-EX3400)

## Requirements

- Python 3.x
- Juniper PyEZ: [`junos-eznc`](https://github.com/Juniper/py-junos-eznc)
- [`lxml`](https://lxml.de/)
- [`requests`](https://docs.python-requests.org/)
- [`jcs`](https://pypi.org/project/jcs/) <sup>(see note below)</sup>

Install python dependencies with:
```bash
pip install junos-eznc lxml requests jcs
```

<sup>Note</sup>:  
The `jcs` module is required for certain Junos automation tasks. If running the script *off-device* (i.e., not directly on Junos OS or Junos-based appliance), you may need to install the [jcs](https://pypi.org/project/jcs/) package from PyPI or follow additional instructions from Juniper Networks if your environment requires it.

## Usage

Run the script locally or from a jump host with network access to the target Junos device or Virtual Chassis. You will need appropriate management credentials.

```
python upgrade_utility.py --host <HOSTNAME_OR_IP> --user <USERNAME> [--password <PASSWORD>] [--root-password <ROOT_PASSWORD>] [--check | --commit] [--no-cleanup]
```

If `--password` is omitted, you will be prompted interactively.
If `--root-password` is omitted, you will be prompted interactively.

### Arguments

- `--host` (required): Hostname or IP of the Junos device.
- `--user` (required): Username for login.
- `--password`: Password (can omit for prompt).
- `--root-password`: Root password for privileged shell operations (can omit for prompt). Required for OAM filesystem mounting.
- `--check`: (default if neither --check nor --commit given) Review and print planned gigether migration configuration, but make NO changes.
- `--commit`: Apply and commit gigether migration configuration, cleanup, and perform software upgrade if required.
- `--no-cleanup`: Skip log and snapshot file cleanup stage.

### Examples

**Preview planned configuration changes (default/dry run):**
```
python upgrade_utility.py --host 192.0.2.1 --user admin --check
```

**Apply migration, cleanup, and perform version upgrade (will commit changes as required):**
```
python upgrade_utility.py --host 192.0.2.1 --user admin --commit --root-password <ROOT_PASS>
```

### Typical Workflow

1. **Preparation**:  
   Ensure the device and Netbox have matching serial/model and target version. Obtain both the standard management and root shell credentials for the device.

2. **Dry Run**:  
   Preview all migration operations and configuration changes:
   ```
   python upgrade_utility.py --host <DEVICE> --user <USERNAME> --check --root-password <ROOT_PASS>
   ```

3. **Apply Migration & Upgrade**:  
   If output looks correct, run with `--commit` to apply and commit changes, perform repd/snapshot cleanup, and (if needed) upgrade the device based on Netbox assignment:
   ```
   python upgrade_utility.py --host <DEVICE> --user <USERNAME> --commit --root-password <ROOT_PASS>
   ```

4. **Review Output**:  
   The script will print detailed output about cleaned files, removed snapshots, generated migration configuration, commit results, and software upgrade steps (including downloading and applying new firmware, installing/removing helper packages, etc).

## Notes

- OAM mounting, delete_remote_file actions, and helper package handling are only performed for non-EX4300 models (e.g., EX2300 and EX3400). On EX4300, these steps are skipped as they are not required.
- The script aborts if any VC member is missing or not present.
- All configuration commits use Junos "commit confirmed" for safety.
- When `--commit` is used, the script will automatically query Netbox for the required firmware version and package corresponding to the device serial/model, download and apply the upgrade if required, and clean up helper packages.
- When privileged shell access is required, the script will prompt for root credentials (or use those supplied in the `--root-password` argument).
- Color-coded output is used for quick status indication.
- For large deployments or automated upgrades, incorporate this script into your pre-upgrade workflow to reduce downtime and prevent upgrade failures due to unsupported configurations.

## Script Structure

The script is organized into distinct, modular steps for clarity and safety:

1. **Argument Parsing & Credential Handling**:  
   Prompts for management/root credentials and parses CLI arguments.
2. **OAM Mount (SSH)**:  
   Uses SSH automation to mount `/dev/gpt/oam/` for necessary upgrade files.
3. **Device Connection & VC Check**:  
   Confirms all chassis members are reachable and in a healthy state.
4. **Cleanup (Logs/Snapshots)**:  
   Deletes unnecessary files and old snapshots using per-model logic.
5. **Configuration Migration**:  
   Detects and migrates deprecated config (`gigether-options` → `ether-options`) and previews safe diffs.
6. **Netbox Lookup & Validation**:  
   Queries the Netbox source of truth for device matching, model validation, and required software version/package.
7. **Software Upgrade**:  
   Downloads/install/removes versioned packages and helper packages as needed, using robust commit/rollback logic.
8. **Colorful Status Output & Error Handling**:  
   Each phase prints clear status and aborts safely if any prereq or op fails.

These steps ensure safe, auditable, and repeatable upgrades. The modular codebase also makes it easy to enhance, debug, or adapt to other Junos workflows.

## Disclaimer

Use at your own risk. Script provided as-is with no warranty. Always test in a lab environment before deploying in production.

