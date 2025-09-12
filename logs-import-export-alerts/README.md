# Import groups

Example of how to import/export Ops for Logs alerts.

If -o is specified, the script writes all alerts to the specified file. If -i is specified, the script
imports alerts from the specified file. If an alert with the same name already exists, the alert is not imported.

## Usage

usage: import-groups [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE]
                     [-i INPUT] [-o OUTPUT] [-U]

Imports groups from a CSV file

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST
  -u USER, --user USER
  -p PASSWORD, --password PASSWORD
  -a AUTHSOURCE, --authsource AUTHSOURCE
  -i INPUT, --input INPUT
  -o OUTPUT, --output OUTPUT
  -U, --unsafe          Ignore certificate validation errors. Not recommended
                        in production