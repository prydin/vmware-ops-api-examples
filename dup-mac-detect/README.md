# Detect duplicate MAC addresses of VMs

List virtual machines that have the same MAC address. 

## Usage

```
python dup-mac-check.py [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] [--unsafe]
```

### Arguments
```
  -h, --help            show this help message and exit
  -H HOST, --host HOST
  -u USER, --user USER
  -p PASSWORD, --password PASSWORD
  -a AUTHSOURCE
  --unsafe              Skip certificate verification. Don't use this in production
```

## Example 
```commandline
python dup-mac-check.py -H vrops.example.com -u admin -p secret  
```
