# Application Layer Attacks - Traffic Analysis (HTB Academy)

## Overview

This report documents the practical traffic analysis exercises completed as part of the Application Layer Attacks module in HTB Academy's Network Traffic Analysis path. The focus areas covered include HTTP/HTTPS fuzzing detection, strange HTTP headers, HTTP request smuggling, cross-site scripting (XSS), SSL renegotiation attacks, and DNS tunneling, all analyzed using Wireshark.

## Tools Used

- Wireshark
- base64 (Linux command line, for decoding exfiltrated DNS tunneling data)

## 1. Detecting HTTP/HTTPS Fuzzing and Directory Enumeration

**PCAP file:** `basic_fuzzing.pcapng`

This exercise focused on identifying directory fuzzing attempts against a web server.

**Filter to isolate all HTTP traffic:**

```
http
```
![1](https://github.com/ilolokerry/Hack-the-box-Labs/blob/d525cecb27c25cf080776e584bdf76effb725911/Network%20Traffic%20Analysis/media/Aplication%20layer%20attacks/HTTPHTTPs%20Service%20Enumeration/1.png)

**Filter to isolate only HTTP requests (removing server responses from view):**

```
http.request
```
![2](https://github.com/ilolokerry/Hack-the-box-Labs/blob/d525cecb27c25cf080776e584bdf76effb725911/Network%20Traffic%20Analysis/media/Aplication%20layer%20attacks/HTTPHTTPs%20Service%20Enumeration/2.png)

The fuzzing attempt was identified by the presence of repeated requests to non-existent file paths in rapid succession, each returning a 404 response, which is a clear signature of automated directory/file brute-forcing.

**Filter to isolate traffic to/from a single suspected host:**

```
http.request and ((ip.src_host == <suspected IP>) or (ip.dst_host == <suspected IP>))
```
![3](https://github.com/ilolokerry/Hack-the-box-Labs/blob/d525cecb27c25cf080776e584bdf76effb725911/Network%20Traffic%20Analysis/media/Aplication%20layer%20attacks/HTTPHTTPs%20Service%20Enumeration/3.png)


I also used Wireshark's Follow HTTP Stream feature (right-click a request → Follow → HTTP Stream) to build a fuller picture of the requests being sent and the corresponding server responses.

## 2. Strange HTTP Headers and Host Header Manipulation

**PCAP file:** `CRLF_and_host_header_manipulation.pcapng`

**Filter to isolate HTTP traffic:**

```
http
```
![1](https://github.com/ilolokerry/Hack-the-box-Labs/blob/d525cecb27c25cf080776e584bdf76effb725911/Network%20Traffic%20Analysis/media/Aplication%20layer%20attacks/Strange%20HTTP%20Headers/1.png)

**Filter to find irregular Host headers (excluding the legitimate server's known IP):**

```
http.request and (!(http.host == "192.168.10.7"))
```
![2](https://github.com/ilolokerry/Hack-the-box-Labs/blob/d525cecb27c25cf080776e584bdf76effb725911/Network%20Traffic%20Analysis/media/Aplication%20layer%20attacks/Strange%20HTTP%20Headers/2.png)

This filter surfaced requests using unexpected Host header values, which can indicate an attacker attempting to manipulate virtual host routing to gain unauthorized access.

### Analyzing HTTP Request Smuggling / CRLF Injection

**Filter to isolate HTTP 400 (Bad Request) responses, a common indicator of request smuggling attempts:**

```
http.response.code == 400
```
![3](https://github.com/ilolokerry/Hack-the-box-Labs/blob/d525cecb27c25cf080776e584bdf76effb725911/Network%20Traffic%20Analysis/media/Aplication%20layer%20attacks/Strange%20HTTP%20Headers/3.png)

Following one of these streams (Follow → HTTP Stream) revealed a CRLF-injected request where the attacker embedded a second, smuggled HTTP request inside the first using encoded carriage-return/line-feed sequences (`%0d%0a`). Decoded, this revealed an attempt to route a second request to an internal-only resource (`127.0.0.1:8080`) that should not have been reachable externally.

![4](https://github.com/ilolokerry/Hack-the-box-Labs/blob/d525cecb27c25cf080776e584bdf76effb725911/Network%20Traffic%20Analysis/media/Aplication%20layer%20attacks/Strange%20HTTP%20Headers/4.png)

## 3. Cross-Site Scripting (XSS) and Code Injection Detection

**PCAP file:** `XSS_Simple.pcapng`

This exercise involved identifying outbound requests to an unrecognized external/internal "server" that indicated cookie or session token theft via injected JavaScript.

**Filter used:**

```
http
```

[SCREENSHOT PLACEHOLDER: Wireshark view showing HTTP requests containing cookie/session values being sent to an unrecognized host]

Following the relevant HTTP stream showed the values being exfiltrated (in this case, session cookies) being sent as URL parameters to an external listener, consistent with a classic XSS payload using `XMLHttpRequest` to exfiltrate `document.cookie`.

[SCREENSHOT PLACEHOLDER: Follow HTTP Stream showing the exfiltration request containing cookie data]

## 4. SSL Renegotiation Attack Detection

**PCAP file:** `SSL_renegotiation_edited.pcapng`

This exercise focused on identifying SSL/TLS renegotiation abuse by inspecting the TLS handshake layer.

**Filter to isolate TLS/SSL handshake messages only (content type 22):**

```
ssl.record.content_type == 22
```

[SCREENSHOT PLACEHOLDER: Wireshark view filtered to handshake messages only]

The key indicator identified was multiple Client Hello messages originating from the same client within a short time window, which is the clearest sign of a forced SSL renegotiation attempt (an attacker repeatedly triggering renegotiation in hopes of forcing a downgrade to a weaker cipher suite). I also reviewed the capture for out-of-order handshake messages, such as a Client Hello arriving after a handshake had already completed, which is another renegotiation indicator.

[SCREENSHOT PLACEHOLDER: Multiple Client Hello messages from the same client]

## 5. DNS Tunneling and Data Exfiltration Detection

**PCAP file:** `dns_tunneling.pcapng`

**Filter to isolate DNS traffic:**

```
dns
```

[SCREENSHOT PLACEHOLDER: DNS traffic view showing a high volume of TXT record queries from a single host]

An unusually high volume of TXT record queries and responses from a single host was identified as a strong indicator of DNS tunneling, since attackers commonly use the TXT field to carry exfiltrated data disguised as legitimate DNS traffic.

Inspecting the TXT record value on the right-hand details pane in Wireshark revealed an encoded string. I copied this value out of Wireshark (right-click → Copy → Value) and decoded it on a Linux machine using base64:

```bash
echo 'VTBaU1EyVXhaSFprVjNocldETnNkbVJXT1cxaU0wb3pXVmhLYTFneU1XeFlNMUp2WVZoT1ptTklTbXhrU0ZJMVdETkNjMXBYUm5wYQpXREJMQ2c9PQo=' | base64 -d
```

This single decode produced another base64-encoded string, indicating the attacker had layered (multi-encoded) the exfiltrated data to add a degree of obfuscation:

```
SFRCe1dvdWxkX3lvdV9mb3J3YXJkX21lX3RoaXNfcGJld8Tlb3J5X3BsZWFzZX0KCg==
```

I decoded the value a second and third time to fully reveal the underlying data:

```bash
echo 'VTBaU1EyVXhaSFprVjNocldETnNkbVJXT1cxaU0wb3pXVmhLYTFneU1XeFlNMUp2WVZoT1ptTklTbXhrU0ZJMVdETkNjMXBYUm5wYQpXREJMQ2c9PQo=' | base64 -d | base64 -d | base64 -d
```

[SCREENSHOT PLACEHOLDER: Terminal output showing the multi-layer base64 decode chain]

This exercise reinforced that exfiltrated data is often base64-encoded (sometimes multiple times) or fully encrypted, and that decoding alone may not always be sufficient if encryption has also been applied.

## Key Takeaways

- HTTP fuzzing and directory enumeration are easily spotted through rapid, repeated 404 responses to a wide variety of file paths from a single host.
- Host header filtering is an effective way to surface virtual host manipulation and request smuggling attempts; HTTP 400 responses are a reliable starting point for investigating CRLF/smuggling activity.
- TLS handshake-layer filtering (`ssl.record.content_type == 22`) is essential for spotting SSL renegotiation abuse, primarily through repeated Client Hello messages.
- DNS TXT record volume is one of the most reliable indicators of DNS tunneling, and exfiltrated values are frequently base64-encoded one or more times before (or instead of) encryption.
