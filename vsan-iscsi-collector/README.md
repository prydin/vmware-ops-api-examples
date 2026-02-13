# vSAN iSCSI Collector

A script for collecting information about vSAN iSCSI LUNs from a vSphere environment and pushing the metrics to vRealize Operations (vROps).

## Quick Start

The easiest way to run the collector is using the provided shell script, which automatically sets up a virtual environment and installs dependencies:

```bash
./run.sh -H <vrops-host> -u <vrops-user> --passwordfile password.txt \
         -V <vcenter-host> -v <vcenter-user> --vcpasswordfile password.txt
```

## Usage

### Using the run.sh script (recommended)

```bash
./run.sh [options]
```

The script will:
1. Create a virtual environment if it doesn't exist
2. Install/update required dependencies
3. Run the collector with the provided arguments

### Direct Python execution

```bash
python3 vsan-iscsi-collector.py [options]
```

### Arguments

```
  -h, --help            show this help message and exit
  -H HOST, --host HOST  vROps host
  -u USER, --user USER  vROps user
  -p PASSWORD, --password PASSWORD
                        vROps password
  --passwordfile PASSWORDFILE
                        vROps password file
  -a AUTHSOURCE, --authsource AUTHSOURCE
                        Authentication source (default: Local)
  -U, --unsafe          Skip certificate checking (unsafe!)
  -v VCUSER, --vcuser VCUSER
                        vCenter user
  -V VCHOST, --vchost VCHOST
                        vCenter host
  -W VCPASSWORD, --vcpassword VCPASSWORD
                        vCenter password
  --vcpasswordfile VCPASSWORDFILE
                        vCenter password file
  --verbose             Enable verbose logging to stderr
```

## Examples

### Using password files (recommended for security)
```bash
./run.sh -H ops.example.com -u admin --passwordfile password.txt \
         -V vc-01.example.com -v administrator@vsphere.local --vcpasswordfile password.txt --verbose
```

### Using passwords directly (not recommended)
```bash
./run.sh -H ops.example.com -u admin -p secret123 \
         -V vc-01.example.com -v administrator@vsphere.local -W vcpassword123
