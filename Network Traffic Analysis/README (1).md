# Network Traffic Analysis - HTB Academy

## Module Description

This module sharpens skills in detecting link layer attacks such as ARP anomalies and rogue access points, identifying network abnormalities like IP spoofing and TCP handshake irregularities, and uncovering application layer threats from web-based vulnerabilities to peculiar DNS activities.

## Module Summary

This intermediate-level module from Hack The Box Academy covers traffic analysis techniques for detecting and mitigating a wide range of cyber threats, broken down into three core areas:

**Detecting Link Layer Attacks**
- ARP-based vulnerabilities, including spoofing, scanning, and denial-of-service attacks
- 802.11 threats, including denial-of-service and deauthentication attacks
- Identifying and mitigating Rogue Access Points and Evil-Twin attacks

**Detecting Network Abnormalities**
- Fragmentation attacks and the intentions behind IP spoofing
- TCP handshake irregularities and connection anomalies such as resets and hijacking
- Covert channels such as ICMP tunneling

**Detecting Application Layer Attacks**
- Web-based threats from HTTP/HTTPS enumeration and HTTP header oddities
- Injection attacks like XSS and Command Injection, and SSL renegotiation attacks
- Suspicious DNS activity and unusual Telnet & UDP connections

## Contents

This repository contains my write-ups for each section of the module, documenting the Wireshark-based traffic analysis exercises completed during the course:

- [`link-layer-attacks-traffic-analysis.md`](./link-layer-attacks-traffic-analysis.md)
- [`application-layer-attacks-traffic-analysis.md`](./application-layer-attacks-traffic-analysis.md)
- [`detecting-network-abnormalities-traffic-analysis.md`](./detecting-network-abnormalities-traffic-analysis.md)

Each report covers the filters and techniques used in Wireshark to identify the relevant attack patterns, along with any decoding steps performed on exfiltrated data.

## Tools Used

- Wireshark
- base64 (Linux CLI)

## Status

Module completed.
