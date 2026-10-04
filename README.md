# Day 1: Multi-Threaded TCP Port Scanner

## Overview
A fast, multi-threaded TCP port scanner written from scratch in Python using standard libraries (`socket`,`concurrent.futures`,`argparse`).

## How It Works
- Uses standard IPv4 stream sockets (`AF_INET`,`SOCK_STREAM`) to attempt TCP handshakes.
- Uses `connect_ex()` to non-destructively determine whether ports are open (return code `0`) or closed.
- Parallelizes socket requests using a configurable `ThreadPoolExecutor` to scan 1,000+ ports in under 2 seconds.
- Performs basic banner grabbing on open HTTP/SSH services.

## Usage
```bash
python scanner.py -t scanme.nmap.org -s 1 -e 1000 -w 100
```
