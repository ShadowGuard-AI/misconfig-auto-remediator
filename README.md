![Banner](banner.png)

# misconfig-Auto-Remediator
A command-line tool that applies the fixes named in a JSON report to a configuration file. Each report entry under `misconfigurations` names a dotted `path` and a `suggested_value`; the tool sets that setting, creating the setting, and any missing sections above it, when it is not already there. A suggested value of `false` or `0` is applied like any other value.

Without `-o` the config file is overwritten in place. That in-place write is the documented default mode of this tool, and naming the config file with `-o` does the same thing. Naming the report file with `-o` is refused at exit 1, because the report is an input. Use `-b` to keep a backup of the original config, and `-d` to print the result without writing anything.

The output keeps the input format: a JSON config comes back as JSON, and a YAML config comes back as YAML with its key order kept. YAML comments are not kept, because the YAML writer this tool uses cannot carry them through a rewrite. A run that applies no entry writes nothing and exits 1 instead of reporting completion, and an empty or non-mapping config is refused at exit 1 rather than written back as a null document.

## Install
`git clone https://github.com/ShadowStrikeHQ/misconfig-auto-remediator`

## Usage
`python3 main.py [params] config_file report_file`

## Parameters
- `config_file`: Path to the configuration file (YAML or JSON). Required.
- `report_file`: Path to the report file (JSON, from Misconfig-Compliance-Checker). Required.
- `-h`: Show help message and exit
- `-o`, `--output_file`: Path to the output file (remediated configuration). If not specified, the input config file is overwritten in place. Naming the report file is refused.
- `-d`, `--dry_run`: Enable dry-run mode. The remediated configuration is printed and no file is written.
- `-b`, `--backup`: Create a backup of the original config file before modification.

## License
Copyright (c) ShadowStrikeHQ
