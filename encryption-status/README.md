# Check vSAN encryption status on VMs based on a tag

This example first runs a query based on a vCenter tag. The backing vSAN datastore is then
examined and its encryption status is displayed. This is useful for checking that all the 
datastores backing an application (as defined by a tag) are encrypted.

## Usage

```
python encryption-status.py [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] [-k ADAPTERKIND] -r RESOURCEKIND -n RESOURCENAME -o OUTPUTFILE
```

### Arguments
```
  -h, --help            show this help message and exit
  -H HOST, --host HOST
  -u USER, --user USER
  -p PASSWORD, --password PASSWORD
  -a AUTHSOURCE, --authsource AUTHSOURCE
  -k ADAPTERKIND, --adapterkind ADAPTERKIND (default is "VMWARE")
  -r RESOURCEKIND, --resourcekind RESOURCEKIND (default is "VirtualMachine")
  -n RESOURCENAME
  -t TAG --tag TAG
  -o OUTPUT --output OUTPUT
 
```

## Example 
```commandline
encyption-status.py -H example.local -u admin -p secret --resourcekind VirtualMachine -t Application-Name=NSX --unsafe
```

Output:
```text
nsx-mgmt-1,Enabled
edge2-mgmt,Disabled
edge1-mgmt,Enabled
nsx1-wld,Enabled
```