# Description

synscapy is a python2, scapy-based utility providing TCP SYN scan services. Since it uses raw sockets, it's supposed to be run with superuser capabilities.

## Usage

```
$ sudo ./synsca.py -h
usage: synsca.py [-h] [-p PORTS] target

scapy-based TCP SYN scanner

positional arguments:
  target      target IP address or hostname

optional arguments:
  -h, --help  show this help message and exit
  -p PORTS    target ports with the input format being a
              comma-separated list of ports and (or) port ranges
              (e.g. 80,135-139,200)
              the default value is 80
              please note that space characters are not allowed
```

## Usage Example

```
$ sudo ./synsca.py -p 1-1024 10.0.2.2
10.0.2.2 is up
started scanning
135 is open (SA)
445 is open (SA)
902 is open (SA)
912 is open (SA)
scanning finished in 3 seconds
```