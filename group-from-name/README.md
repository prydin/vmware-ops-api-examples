# Import groups

Example of creating custom groups based on patterns in VM names.

As an example, suppose we have a name format on the form "<app code>-<location>-<serial number>". A set of VMs could be
names as follows:

```text
app1-ny-0001
app1-ca-0002
app1-nj-003
app2-nj-004
app2-tx-005
```
Let's say we want to create custom groups that look at the letters before the first hyphen. We could write a regexp that 
handles that like this ```^([^\-]+)-.*``` that would isolate all non-hyphen characters before the first hyphen. Those
characters would be used to create the group name. The group selection criteria would become e.g. ```^app1-.*```.

This way, we end up with groups that are named based on the application code and has a selection criteria that dynamically
selects all VMs matching that name.

## Usage

```
python groups-from-name.py [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] -A
                        APPREGEX [-f FILTERREGEX] [-U] [-l LIMIT] [-F]
```

### Arguments
```
usage: groups-from-name [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] -A
                        APPREGEX [-f FILTERREGEX] [-U] [-l LIMIT] [-F]

Creates groups based on VM names

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  The VCF Operations host
  -u USER, --user USER  The VCF Operations user
  -p PASSWORD, --password PASSWORD
                        The VCF Operations password
  -a AUTHSOURCE, --authsource AUTHSOURCE
                        The VCF Operations authentication source
  -A APPREGEX, --appregex APPREGEX
                        Regexp for obtaining application name from VM name
  -f FILTERREGEX, --filterregex FILTERREGEX
                        Regexp to filter VMs by name (defauls is all VMs)
  -U, --unsafe          Ignore certificate validation errors. Not recommended
                        in production
  -l LIMIT, --limit LIMIT
                        Limit number of VMs to process. Useful for
                        testing/debugging
  -F, --force           Force replacement of existing groups
```

## Example
```bash
python group-from-name.py -H vcf-ops.local -u admin -h -p secret -f "^[^-]+-[A-Za-z]+" -A "^(.+)-.*" --unsafe
``` 
