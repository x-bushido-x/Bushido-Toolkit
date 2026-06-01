# BushidoMap - Network Scanner

A powerful Python-based network scanning tool inspired by nmap, providing port scanning and host discovery capabilities.

## Features

- TCP port scanning (SYN, Connect)
- UDP port scanning
- Host discovery (ping sweep)
- Service and version detection
- Multiple scan modes
- Concurrent scanning for performance
- Export results to JSON/XML

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Basic port scan
python bushidomap.py -t 192.168.1.1 -p 80,443,8080

# Scan range of ports
python bushidomap.py -t 192.168.1.1 -p 1-1000

# Scan multiple hosts
python bushidomap.py -t 192.168.1.1-10 -p 80,443

# Scan CIDR range
python bushidomap.py -t 192.168.1.0/24 -p 22,80,443

# Service detection
python bushidomap.py -t 192.168.1.1 -p 1-1000 -sV

# SYN scan (requires root/admin)
python bushidomap.py -t 192.168.1.1 -p 1-1000 -sS

# UDP scan
python bushidomap.py -t 192.168.1.1 -p 53,161 -sU

# Skip host discovery
python bushidomap.py -t 192.168.1.1 -p 1-1000 -Pn

# Aggressive timing
python bushidomap.py -t 192.168.1.1 -p 1-1000 -T4

# Save results to JSON
python bushidomap.py -t 192.168.1.1 -p 1-1000 -o results.json

# Verbose output
python bushidomap.py -t 192.168.1.1 -p 1-1000 -v
```

## Timing Templates

| Template | Level | Description     |
|----------|-------|-----------------|
| -T0      | 0     | Paranoid (slow) |
| -T1      | 1     | Sneaky          |
| -T2      | 2     | Polite          |
| -T3      | 3     | Normal (default)|
| -T4      | 4     | Aggressive      |
| -T5      | 5     | Insane (fast)   |

## Requirements

- Python 3.8+
- Root/Administrator privileges for SYN scanning
