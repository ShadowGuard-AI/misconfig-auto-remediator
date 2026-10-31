import argparse
import json
import logging
import os
import sys
import tempfile
import shutil
import subprocess
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argparse argument parser.
    """
    parser = argparse.ArgumentParser(description="Automatically remediates misconfigurations in configuration files.")
    parser.add_argument("config_file", help="Path to the configuration file.")
    parser.add_argument("report_file", help="Path to the report file (from Misconfig-Compliance-Checker).")
    parser.add_argument("-o", "--output_file", help="Path to the output file (remediated configuration). If not specified, overwrites the input config file: naming the config file itself is the documented in-place mode. Naming the report file is refused.", default=None)
    parser.add_argument("-d", "--dry_run", action="store_true", help="Enable dry-run mode (no changes are written to the file).")
    parser.add_argument("-b", "--backup", action="store_true", help="Create a backup of the original config file before modification.")
    return parser


def load_config(config_file):
    """
    Loads the configuration file (YAML or JSON).
    """
    try:
        with open(config_file, "r") as f:
            text = f.read()
        # Detect the format from the extension, falling back to content, so
        # a JSON config is written back as JSON and not converted to YAML.
        lower = config_file.lower()
        if lower.endswith(".json"):
            fmt = "json"
        elif lower.endswith((".yaml", ".yml")):
            fmt = "yaml"
        elif text.lstrip().startswith(("{", "[")):
            fmt = "json"
        else:
            fmt = "yaml"
        if fmt == "json":
            try:
                return json.loads(text), "json"
            except json.JSONDecodeError:
                raise ValueError("Configuration file is not valid JSON.")
        try:
            return yaml.safe_load(text), "yaml"
        except yaml.YAMLError:
            raise ValueError("Configuration file is not valid YAML or JSON.")
    except FileNotFoundError:
        raise FileNotFoundError(f"Configuration file not found: {config_file}")
    except Exception as e:
        raise Exception(f"Error loading configuration file: {e}")



def load_report(report_file):
    """
    Loads the report file (JSON).
    """
    try:
        with open(report_file, "r") as f:
            report = json.load(f)
            return report
    except FileNotFoundError:
        raise FileNotFoundError(f"Report file not found: {report_file}")
    except json.JSONDecodeError:
        raise ValueError("Report file is not valid JSON.")
    except Exception as e:
        raise Exception(f"Error loading report file: {e}")


def remediate_misconfiguration(config, misconfiguration):
    """
    Remediates a single misconfiguration based on the report.

    This is a placeholder for actual remediation logic.  It should
    be expanded with specific remediation strategies for different
    types of misconfigurations.  For security reasons, avoid direct
    code execution or string formatting that could lead to injection
    attacks. Use safe methods for updating the configuration.

    Args:
        config (dict): The configuration dictionary.
        misconfiguration (dict): A dictionary containing the misconfiguration details
                                  from the report.  It should include information
                                  like the path to the misconfigured setting,
                                  the expected value, and any other relevant data.

    Returns:
        bool: True if a value was applied or created, False if skipped.
    """
    logging.info(f"Attempting to remediate misconfiguration: {misconfiguration}")
    try:
        # Example Remediation (Replace with actual logic)
        # This example assumes the misconfiguration report contains a 'path'
        # (e.g., "security.password_policy.minimum_length") and a 'suggested_value'.

        path = misconfiguration.get("path")
        # A suggested value of False, 0, or an empty string is a real
        # remediation. Only a missing key or a None value is missing.
        if not path or "suggested_value" not in misconfiguration or misconfiguration.get("suggested_value") is None:
            logging.warning(f"Missing 'path' or 'suggested_value' in misconfiguration report. Skipping remediation.")
            return False
        suggested_value = misconfiguration.get("suggested_value")

        if not isinstance(config, dict):
            logging.warning(f"Configuration is not a mapping. Skipping remediation.")
            return False

        parts = path.split(".")
        current = config

        for i in range(len(parts) - 1):
            if parts[i] not in current:
                logging.info(f"Creating missing section '{parts[i]}' for path '{path}'")
                current[parts[i]] = {}
            if not isinstance(current[parts[i]], dict):
                logging.warning(f"Path '{path}' passes through a non-mapping value. Skipping remediation.")
                return False
            current = current[parts[i]]

        last_part = parts[-1]
        if last_part in current:
            logging.info(f"Changing value of '{path}' from '{current[last_part]}' to '{suggested_value}'")
        else:
            logging.info(f"Creating setting '{path}' with value '{suggested_value}'")
        current[last_part] = suggested_value
        return True


    except Exception as e:
        logging.error(f"Error remediating misconfiguration: {e}")
        return False


def write_config(config, output_file, config_type):
    """
    Writes the configuration to a file (YAML or JSON).
    """
    try:
        with open(output_file, "w") as f:
            if config_type == "yaml":
                yaml.dump(config, f, indent=2, sort_keys=False)
            elif config_type == "json":
                json.dump(config, f, indent=2)
            else:
                raise ValueError("Invalid config_type. Must be 'yaml' or 'json'.")
    except Exception as e:
        raise Exception(f"Error writing configuration file: {e}")


def main():
    """
    Main function to execute the misconfig-Auto-Remediator tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    config_file = args.config_file
    report_file = args.report_file
    output_file = args.output_file
    dry_run = args.dry_run
    backup = args.backup

    # Input validation
    if not os.path.exists(config_file):
        logging.error(f"Configuration file not found: {config_file}")
        sys.exit(1)

    if not os.path.exists(report_file):
        logging.error(f"Report file not found: {report_file}")
        sys.exit(1)


    if output_file and os.path.realpath(output_file) == os.path.realpath(report_file):
        logging.error("Output path resolves to the report file. Refusing to overwrite the report.")
        sys.exit(1)

    try:
        # Load configuration and report
        config, config_type = load_config(config_file)
        if not isinstance(config, dict):
            logging.error("Configuration file does not hold a mapping of settings. Nothing was remediated.")
            sys.exit(1)
        report = load_report(report_file)

        # Remediate misconfigurations
        misconfigurations = report.get("misconfigurations", [])
        applied = 0
        if not misconfigurations:
            logging.info("No misconfigurations found in the report.")
        else:
            for misconfiguration in misconfigurations:
                if remediate_misconfiguration(config, misconfiguration):
                    applied += 1

        if applied == 0:
            logging.error("No remediations were applied. The configuration file was not written.")
            sys.exit(1)

        # Backup the original config file if requested, only now that a
        # write is actually going to happen
        if backup and not dry_run:
            backup_file = config_file + ".bak"
            shutil.copy2(config_file, backup_file)
            logging.info(f"Backup created: {backup_file}")

        # Write the remediated configuration
        if dry_run:
            logging.info("Dry-run mode enabled. No changes will be written to file.")
            if config_type == "yaml":
                print(yaml.dump(config, indent=2, sort_keys=False))
            elif config_type == "json":
                print(json.dumps(config, indent=2))
        else:
            if output_file:
                output_file_path = output_file
            else:
                output_file_path = config_file  # Overwrite the original file if no output file is specified
            write_config(config, output_file_path, config_type)
            logging.info(f"Remediated configuration written to: {output_file_path}")

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)

    logging.info("Misconfig-Auto-Remediator completed.")


if __name__ == "__main__":
    main()