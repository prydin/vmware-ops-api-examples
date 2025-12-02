# Relationship Builder Example

Example script that forms a relationship between two existing objects in VCF Ops

## Description
This example script builds relationships between two existing objects in VCF Ops by using a property to map
it to the name of a related object. The mapping can be done using a regular expression.
## Usage

```
python rel-builder [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] --reltype RELTYPE --sourcekind SOURCEKIND --targetkind TARGETKIND
                   --property PROPERTY [--matchre MATCHRE] [--extractre EXTRACTRE] [--ignorecase] [-U]
```

### Arguments
```
options:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  The address of the VCF Ops host
  -u USER, --user USER  The VCF Ops user
  -p PASSWORD, --password PASSWORD
                        The VCF Ops password
  -a AUTHSOURCE, --authsource AUTHSOURCE
                        The VCF Ops authentication source. Default is Local
  --reltype RELTYPE     Relation type to create (CHILD/PARENT)
  --sourcekind SOURCEKIND
                        Resource kind of source
  --targetkind TARGETKIND
                        Resource kind of target
  --property PROPERTY   Property used for linking
  --matchre MATCHRE     Name matching regular expression
  --extractre EXTRACTRE
                        Name extraction regular expression
  --ignorecase          Ignore case in name matching
  -U, --unsafe          Skip certificate checking (this is unsafe!)
```

## Example
Map a resource of type BladeServer from the adapter kind Test to an ESX-host using the property "esx". This property is on the form 
"esx-01.example.com" and we want to extract just "esx-01" to match the ESX-host name. The hosts are named e.g. "my-host-esx-01".
The relationship type to create is CHILD.

The {} in the matchre argument is replaced with the extracted name.

```commandline
python rel-builder.py -H ops.example.com -u admin -p secret -U --sourcekind Test:BladeServer --targetkind HostSystem --extractre "(.*)\.example.com" --matchre "my-host-{}" --property esx --reltype CHILD 
```