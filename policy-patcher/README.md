 # Policy Patcher

Utility for patching policies in VCF Operations (vROps) by exporting the policy as XML,
applying an XPath-based replacement from a local XML file, and re-importing the modified policy.

## Usage

```commandline
python policy-patcher.py [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] -n NAME -f FILE [-e EXPRESSION] [-U] [-v]
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
  -f FILE, --file FILE  Path to XML file containing the replacement XML element
  -e EXPRESSION, --expression EXPRESSION
                        XPath expression to select the element to patch in the exported policy
  -U, --unsafe          Skip certificate checking (this is unsafe!)
  -v, --verbose         Enable verbose/debug logging
```

## Example

Patch a policy named "Test policy" by replacing the element selected by an XPath expression
with the contents of a local XML file:

```commandline
python policy-patcher.py -u admin -H 192.168.1.220 --unsafe \
  -n "Test policy" \
  -e "$.capacitySettings.capacity.capacityBufferSettings[0].capacityBuffer" \
  -f update.xml
```

## Input File

The patch file must be a valid XML fragment whose root element will replace all child elements
of the node(s) matched by the XPath expression. For example:

```xml
<capacityBuffer>
  <bufferPercent>20</bufferPercent>
</capacityBuffer>
```

## How It Works

1. The policy is exported from VCF Ops as a zip archive containing `exportedPolicies.xml`.
2. The XPath expression is evaluated against the exported XML.
3. The children of each matched element are replaced with the root element from the input file.
4. The modified XML is re-packaged into a new in-memory zip archive and imported back via `POST /api/policies/import`.

## Notes

- The XPath expression must resolve to one or more XML elements within the exported policy.
- Use `--verbose` to print detailed debug information, including the XML before and after patching.
- Use `--unsafe` only in lab/development environments with self-signed certificates.
