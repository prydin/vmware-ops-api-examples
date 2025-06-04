# Import groups

Example of creating custom groups based on a simple CSV file.

## Usage

```
python group-import.py [-h] -H HOST -u USER -p PASSWORD [-a AUTHSOURCE] [-c CSVFILE] [-U]
```

### Arguments
```
  -h, --help 
  -H HOST, --host HOST
  -u USER, --user USER
  -p PASSWORD, --password PASSWORD
  -a AUTHSOURCE, --authsource AUTHSOURCE
  -c CSVFILE, --csvfile CSVFILE
  -U, --unsafe

```

## Example 

### Input data

Each line links an application to a VM, e.g. `vcf-ops-vcf01 is part of` `app1`

```csv
app1,vcf-ops-vcf01
app1,vcf-ops-vrli-vc01
app1,vcf-ops-vrli-vc01-nsx01c
app2,vcf-ops-vrli-vc02
app2,vcfops-pp-esx07
```

### Command line

```commandline
python generate_report.py -H vrops.example.com -u admin -p secret -c data.csv
```
