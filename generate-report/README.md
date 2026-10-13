# Run or download a report

Run an Operations report and download the result as CSV or PDF, or download its latest completed run without generating a new report.

## Usage

```
python generate-report.py [-h] -H HOST [-u USER -p PASSWORD | -t API_TOKEN -I IDB_URL] [-a AUTHSOURCE] [-k ADAPTERKIND] -r RESOURCEKIND -n RESOURCENAME -R REPORTNAME [-o OUTPUT] [--format {pdf,csv}] [-N] [-U]
```

### Arguments
```
  -h, --help            show this help message and exit
  -H HOST, --host HOST                  Operations host name or IP address (required)
  -u USER, --user USER                  User name for password authentication
  -p PASSWORD, --password PASSWORD      Password for password authentication
  -t API_TOKEN, --api-token API_TOKEN    VCF 9.1+ API token; requires --idb-url
  -I IDB_URL, --idb-url IDB_URL          Identity Broker host or full token endpoint URL
  -a AUTHSOURCE, --authsource AUTHSOURCE Identity source for password authentication
  -k ADAPTERKIND, --adapterkind ADAPTERKIND
                                       Adapter kind (default: VMWARE)
  -r RESOURCEKIND, --resourcekind RESOURCEKIND
                                       Resource kind (required)
  -n RESOURCENAME, --resourcename RESOURCENAME
                                       Resource name (required)
  -R REPORTNAME, --reportname REPORTNAME Report definition name (required)
  -o OUTPUT, --output OUTPUT            Output file; otherwise CSV goes to stdout
  --format {pdf,csv}                    Download format (default: csv)
  -N, --nogenerate                      Download the latest completed matching run
  -U, --unsafe                          Disable TLS certificate validation
```

### Authentication

Specify either `--user` and `--password`, or `--api-token` and `--idb-url`. API-token authentication is for VCF 9.1+ (including 9.1.1); neither token-mode option can be combined with `--user` or `--password`. `--authsource` is only used for password authentication.

For API-token authentication, the script exchanges the API token at the Identity Broker for a bearer token. A bare broker host name or base URL, such as `idb.example.com` or `https://idb.example.com`, uses `/acs/t/CUSTOMER/token`. To use a different tenant, supply the full token endpoint URL, such as `https://idb.example.com/acs/t/<tenant>/token`.

### Download behavior

- By default, the script starts a new report run and waits for it to complete.
- `--nogenerate` skips report execution and downloads the latest completed run matching the report definition and the resource selected by name, resource kind and adapter kind. If no completed matching run exists, the script prints an error and exits with a nonzero status.
- `--format csv` is the default and supports either `--output` or stdout.
- `--format pdf` requires `--output`. Without it, the script prints an error and exits before contacting the API. The report definition must produce PDF output.
- `--unsafe` disables certificate validation for both Operations and Identity Broker requests. It is not recommended in production.

## Examples

Run a report using password authentication and write CSV to stdout:

```commandline
python generate-report.py -H vrops.example.com -u admin -p "<password>" -r VirtualMachine -n "My VM" -R "My Report"
```

Download an existing report using API-token authentication:

```commandline
python generate-report.py --host ops.example.com --api-token "<api-token>" --idb-url idb.example.com --adapterkind VMWARE --resourcekind HostSystem --resourcename esx-01.example.com --reportname "Capacity Report - Datastores" --nogenerate --format csv --output report.csv
```

Generate a report and save it as PDF:

```commandline
python generate-report.py -H ops.example.com -u admin -p "<password>" -r VirtualMachine -n "My VM" -R "My Report" --format pdf --output report.pdf
```
