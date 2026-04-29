# Network Router — Data Plane Implementation

A router data plane implemented in C as part of the Computer Networks course at POLITEHNICA Bucharest.

## Overview

This project implements the data plane of a router, handling real network traffic including packet forwarding, ARP resolution, and ICMP messaging.

## Features

- **IPv4 Forwarding** — Longest Prefix Match (LPM) lookup using a routing table
- **ARP Handling** — Generates and processes ARP requests/replies to resolve MAC addresses
- **ICMP Support** — Handles echo requests (ping) and generates error messages (TTL exceeded, host unreachable)
- **TTL Management** — Decrements TTL and drops packets when TTL reaches 0
- **Checksum Validation** — Verifies and recomputes IP/ICMP checksums

## Implementation Details

- Parses raw Ethernet frames and inspects IP headers
- Maintains an ARP cache to avoid redundant ARP requests
- Queues packets waiting for ARP resolution
- Handles `ntohs()`/`htons()` conversions correctly for cross-platform compatibility

## Technologies

- C, POSIX sockets, Ethernet/IP/ARP/ICMP protocols
