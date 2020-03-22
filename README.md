# ARP Spoofing detector

Scan all the ARP packet sent to the selected network interface and print a text if there is an attack.

# Tech part

This script uses a number of open source projects to work properly:

- scapy
- argparse
- python3

### Installation

```
pip install scapy 
pip install argparse
```

### Usage

```
usage: main.py [-h] [-i INTERFACE]

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --ip INTERFACE
                        Write the network interface
```

```
python3 main.py -i enO
```

### Pictures

[![N|Solid](https://i.imgur.com/qcdg6Wo.png)](https://i.imgur.com/qcdg6Wo.png)

@LasCC
