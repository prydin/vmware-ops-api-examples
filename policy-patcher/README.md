# Policy Patcher

Utility for patching policy settings in VCF Operations (vROps) by applying a JSON file to one or more objects selected with a JSONPath expression.

## Usage

```commandline
python policy-patcher.py [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] -n NAME -t TYPE [-k ADAPTER_KIND] -r RESOURCE_KIND -f FILE -e EXPRESSION [-U]
```

### Arguments
```
  -h, --help            show this help message and exit
  -H HOST, --host HOST  The address of the VCF Ops host
  -u USER, --user USER  The VCF Ops user
  -p PASSWORD, --password PASSWORD
                        The VCF Ops password
  -a AUTHSOURCE, --authsource AUTHSOURCE
                        The VCF Ops authentication source. Default is Local
  -n NAME, --name NAME  The name of the policy to patch
  -t TYPE, --type TYPE  Policy type
  -k ADAPTER_KIND, --adapter-kind ADAPTER_KIND
                        Adapter kind for policy settings (default: VMWARE)
  -r RESOURCE_KIND, --resource-kind RESOURCE_KIND
                        Resource kind for policy settings
  -f FILE, --file FILE  Path to JSON file containing the properties to patch
  -e EXPRESSION, --expression EXPRESSION
                        JSONPath expression to select properties to patch from the file
  -U, --unsafe          Skip certificate checking (this is unsafe!)
```

## Example

Patch a policy named "Test policy" for `ClusterComputeResource` settings by updating the capacity buffer setting:

```commandline
python policy-patcher.py -H 192.168.1.220 -u admin --unsafe \
  -n "Test policy" -t "CAPACITY_BUFFER" -r ClusterComputeResource \
  -e "$.capacitySettings.capacity.capacityBufferSettings[0].capacityBuffer" \
  -f update.json
```

## Input File

The patch file must be valid JSON. The example below merges CPU, memory, and diskspace settings into the selected policy settings object:

```json
{
  "cpu": {
    "demand": 11.0,
    "allocation": 11.0
  },
  "memory": {
    "demand": 11.0,
    "allocation": 11.0
  },
  "diskspace": {
    "demand": 11.0,
    "allocation": 11.0
  }
}
```

## Notes

- The JSONPath expression must resolve to one or more JSON objects. Each matched object is updated in place with the contents of the patch file.
- You can inspect the policy settings payload by running the script once and reviewing the printed output.
