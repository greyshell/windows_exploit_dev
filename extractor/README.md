## Description
`extractor.py` is multi-threaded scanner and enumerator.

1. Quickly identifies all open TCP & UDP ports through asynchronous-stateless-scanner `unicornscan`.
2. Feeds results to `nmap` for fingerprinting the running services.
3. Enumerate deeper and extracts more information to determine the vulnerable entry point.

### Usage
```sh
Usage: python extractor.py -H <target host>

Options:
  -h, --help  show this help message and exit
  -H HOST     specify target host
  -M TARGETS  provide a text file (i.e. targets.txt) to scan multiple hosts
              where each host should be separated by a new line

```

### Dependency
- Download and copy `vulscan.zip` (compiled scripts based on cve, exploitdb, openvas) inside `/usr/share/nmap/scripts/vulscan` folder.

### Reference
- `Recon Scan` : http://www.securitysift.com/offsec-pwb-oscp/

