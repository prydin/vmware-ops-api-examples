# Host Profile Collector

A simple script for collecting information about host profiles in a vSphere environment.

## Usage

```
python host-profile-collector.py [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] [-k ADAPTERKIND] -r RESOURCEKIND -n RESOURCENAME -m METRIC [-U UNIT]
```

### Arguments
```
  usage: host-profile-collector.py [-h] -H HOST -u USER -p PASSWORD
                                 [-a AUTHSOURCE] [-U] -v VCUSER -V VCHOST -W
                                 VCPASSWORD [--verbose]
optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  vROps host
  -u USER, --user USER  vROps user
  -p PASSWORD, --password PASSWORD
                        vROps password
  -a AUTHSOURCE, --authsource AUTHSOURCE
                        Authentication source (default: Local)
  -U, --unsafe          Skip certificate checking (unsafe!)
  -v VCUSER, --vcuser VCUSER
                        vCenter user
  -V VCHOST, --vchost VCHOST
                        vCenter host
  -W VCPASSWORD, --vcpassword VCPASSWORD
                        vCenter password
  --verbose             Enable verbose logging to stderr
```

## Example 
```commandline
python -H ops.example.com -u admin -p secret --vchost vc-01.example,com --vcuser administrator@vsphere.local --vcpassword secret`
``
