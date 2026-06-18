# Link Layer Attacks - Traffic Analysis (HTB Academy)

## Overview

This report documents the practical traffic analysis exercises completed as part of the Link Layer Attacks module in HTB Academy's Network Traffic Analysis path. The focus areas covered include ARP spoofing detection, ARP scanning, 802.11 deauthentication attacks, and rogue/evil-twin access point detection, all analyzed using Wireshark.

## Tools Used

- Wireshark

## 1. ARP Spoofing Detection

**PCAP file:** `ARP_Spoof.pcapng`

ARP spoofing attacks were identified by filtering for ARP traffic and looking for IP-to-MAC address inconsistencies, which is a key indicator of a poisoned ARP cache.

**Filter applied to view all ARP requests and replies:**

```
arp.opcode
```

**Filter to isolate ARP requests only:**

```
arp.opcode == 1
```
![1](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/arp/1.png)

Applying this filter surfaced a Wireshark-generated warning for a duplicate IP address mapped to two different MAC addresses, which is the primary indicator of ARP cache poisoning.

[SCREENSHOT PLACEHOLDER: Wireshark view showing the arp.opcode == 1 filter and the duplicate address warning]

**Filter to find duplicate address detections specifically among ARP replies:**

```
arp.duplicate-address-detected && arp.opcode == 2
```
![2](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/arp/2.png)
![2.1](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/arp/2.1.png)

[SCREENSHOT PLACEHOLDER: Filtered view showing duplicate-address-detected replies]

### Tracing the Original IP Address

To determine which MAC address belonged to the legitimate host versus the attacker, I traced historical IP-to-MAC associations using:

```
(arp.opcode) && ((eth.src == 08:00:27:53:0c:ba) || (eth.dst == 08:00:27:53:0c:ba))
```
![3](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/arp/3.png)

This revealed that the MAC address `08:00:27:53:0c:ba` was originally associated with a different IP address before the change occurred, confirming spoofing activity rather than a legitimate network change.

**Filter to inspect all traffic between the two relevant MAC addresses:**

```
eth.addr == 50:eb:f6:ec:0e:7f or eth.addr == 08:00:27:53:0c:ba
```

This filter was used to check whether the attacker was actively forwarding traffic (indicating a full man-in-the-middle position) or simply dropping it (indicating a denial-of-service condition), by observing whether TCP connections between the victim and router were completing normally or failing.

![4](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/arp/4.png)

## 2. ARP Scanning Detection

**PCAP file:** `ARP_Scan.pcapng`

ARP scanning was identified using the same opcode filter as above:

```
arp.opcode
```

The capture showed a single host broadcasting ARP requests to sequential IP addresses (.1, .2, .3, etc.), which is a strong indicator of automated host discovery tools such as Nmap. Active hosts could be seen responding via ARP replies, confirming successful enumeration by the scanning host.

![1](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/ARP%20Scanning%20%26%20Denial-of-Service/1.png)

## 3. ARP-Based Denial-of-Service Detection

**PCAP file:** `ARP_Poison.pcapng`

Following on from scanning, this capture showed an attacker pivoting from host discovery to a broader ARP cache poisoning campaign across the subnet. The traffic showed the attacker's machine repeatedly announcing new MAC-to-IP mappings for live IP addresses, and duplicate allocation of the same IP (the gateway) across multiple client devices, consistent with an attempt to corrupt ARP caches network-wide.

![d1](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/ARP%20Scanning%20%26%20Denial-of-Service/d%201.png)
![d2](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/ARP%20Scanning%20%26%20Denial-of-Service/d2.png)

## 4. 802.11 Deauthentication Attack Detection

**PCAP file:** `deauthandbadauth.cap`

This exercise involved analyzing 802.11 (Wi-Fi) management frames to detect deauthentication-based denial-of-service attacks.

**Filter to isolate traffic from a specific BSSID:**

```
wlan.bssid == xx:xx:xx:xx:xx:xx
```
![1.5](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/802.11%20Denial%20of%20Service/1.5.png)
**Filter to isolate deauthentication frames specifically (management frame type 00, subtype 12):**

```
(wlan.bssid == xx:xx:xx:xx:xx:xx) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12)
```

This filter, applied with the actual BSSID from the capture, revealed an excessive volume of deauthentication frames being sent to a single client device.

![2](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/802.11%20Denial%20of%20Service/2.png)

Inspecting the fixed parameters under the wireless management section of one of these frames showed **reason code 7**, which is the default reason code used by common deauthentication attack tools such as aireplay-ng and mdk4.

```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 7)
```

![3](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/802.11%20Denial%20of%20Service/3.png)

### Identifying Reason Code Rotation (Evasion Technique)

To simulate detection of a more evasive attacker rotating reason codes to avoid alerting, I tested filters incrementing through reason codes individually:

```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 1)
```

```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 2)
```

```
(wlan.bssid == F8:14:FE:4D:E6:F1) and (wlan.fc.type == 00) and (wlan.fc.type_subtype == 12) and (wlan.fixed.reason_code == 3)
```
![4](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/802.11%20Denial%20of%20Service/4.png)


## 5. Rogue Access Point and Evil-Twin Detection

**PCAP file:** `rogueap.cap`

This exercise focused on differentiating a legitimate access point from an evil-twin access point broadcasting the same ESSID.

**Filter to isolate beacon frames (management frame type 00, subtype 8):**

```
(wlan.fc.type == 00) and (wlan.fc.type_subtype == 8)
```
![1](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/Rogue%20Access%20Point%20%26%20Evil-Twin%20Attacks/1.png)

By examining the Robust Security Network (RSN) information within the beacon frames, I compared the legitimate access point's advertised security capabilities (WPA2 with AES/TKIP and PSK authentication) against the suspicious access point, which was missing RSN information entirely, indicating an open, unencrypted evil-twin AP.

![1.5](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/Rogue%20Access%20Point%20%26%20Evil-Twin%20Attacks/1.5.png)


### Identifying Compromised Clients

To find clients that had connected to the rogue/evil-twin AP, I filtered for all traffic on the suspicious BSSID:

```
(wlan.bssid == F8:14:FE:4D:E6:F2)
```

Because the evil-twin AP was unencrypted, higher-layer traffic from connected clients was visible in plaintext. ARP requests originating from a client device on this BSSID were used to identify the MAC address and hostname of a compromised client for follow-up incident response.

![2](https://github.com/ilolokerry/Hack-the-box-Labs/blob/3e9442224ac337ae38dc1814a53e02418a581402/Network%20Traffic%20Analysis/media/Link%20Layers%20Attacks/Rogue%20Access%20Point%20%26%20Evil-Twin%20Attacks/2.png)

## Key Takeaways

- ARP-based attacks are often the first and easiest layer to inspect for anomalies, since most attacks are broadcast in nature.
- Duplicate IP-to-MAC mappings and Wireshark's built-in duplicate address detection warnings are reliable, fast indicators of ARP spoofing.
- 802.11 management frame analysis (deauthentication reason codes, beacon RSN fields) is essential for differentiating legitimate wireless disruptions from deliberate attacks.
- Evil-twin access points can often be distinguished by inconsistencies in security capability advertisements (RSN information) even when ESSIDs are spoofed identically.
