# Synprobe

Synprobe is a port scanning and service detection tool designed to identify open ports and recognize server types based on their response to specific network requests.

## Overview

**Synprobe** operates with two main functionalities:

### SYN-Scanning
Determines the status of ports:
- Sends a SYN packet to a port.
- If a SYN-ACK response is received, the port is considered open. Otherwise, it's closed.

### Service Fingerprinting
Identifies server types through several probing techniques:
- **TLS Probing:**
  - Attempts to establish a TLS connection; a successful connection indicates a TLS server initiated.
  - Reads 1024 bytes from the server:
    - If data is received, the port is classified as a TLS server.
    - If no data is received, an HTTP GET request is sent.
    - Based on the response to the GET request, the server can be classified as HTTPS or a generic TLS server if no other distinctive signs are noted.
- **TCP Probing:**
  - If TLS probing fails (unable to establish a TLS connection), the process attempts to establish a basic TCP connection.
  - Observes the behavior or response from the server to classify it. If no distinctive response is received, the port may be considered a generic TCP server.

This approach ensures that the probing starts with TLS to confirm secure server types first and then resorts to TCP if TLS characteristics are not found, maintaining a structured method of server identification.

## Installation

Requires Python 3 and the Scapy library. Install Scapy using pip:

```bash
pip install scapy
```

## Usage

Run `sudo synprobe.py` with the following options:

```bash
sudo python3 synprobe.py [-p port_range] <target>
```

- `-p` — Specify a single port or a range of ports (e.g., X-Y).
- `<target>` — IP address of the host to scan.

## Sample Test Cases

### Test Case 1: TCP Server-Initiated
- **FTP Server Example:**
  ```bash
  sudo python3 synprobe.py -p 21 ftp.dlptest.com
  ```
  Output: `Port 21 [TCP server-initiated]: 220 Welcome to the DLP Test FTP Server`

- **SMTP Server Example:**
  ```bash
  sudo python3 synprobe.py -p 25 smtp.gmail.com
  ```
  Output: ``

### Test Case 2: TLS Server-Initiated
- **IMAP over TLS Example:**
  ```bash
  sudo python3 synprobe.py -p 993 imap.gmail.com
  ```
  Output: `Port 993 [TLS server-initiated]: * OK Gimap ready for requests from 130.245.192.1 o13mb112291239qtw`

- **SMTP over SSL Example:**
  ```bash
  sudo python3 synprobe.py -p 465 smtp.gmail.com
  ```
  Output: `Port 465 [TLS server-initiated]: 220 smtp.gmail.com ESMTP y22-20020a05620a09d600b0078d5f7b9a2dsm1631932qky.15 - gsmtp`

### Test Case 3: HTTP Server
- **HTTP Example:**
  ```bash
  sudo python3 synprobe.py -p 80 www.cs.stonybrook.edu
  ```
  Output: 
  `
    Port 80 [HTTP Server]: HTTP/1.1 404 Unknown site
    Connection: close
    Content-Length: 566
    Retry-After: 0
    Server: Pantheon
    Cache-Control: no-cache, must-revalidate
    Content-Type: text/html; charset=utf-8
    X-pantheon-serious-reason: The page could not be loaded properly.
    Date: Fri, 03 May 2024 23:43:37 GMT
    X-Served-By: cache-lga21954-LGA
    X-Cache: MISS
    X-Cache-Hits: 0
    X-Timer: S1714779818.782200,VS0,VE28
    Vary: Cookie
    Age: 0
    Accept-Ranges: bytes
    Via: 1.1 varnish

    <!DOCTYPE HTML>
        <html>
            <head>
            <title>404 - Unknown site</title>
            </head>
            <body style="font-family:Arial, Helvetica, sans-serif; text-align: center">
            <div style='padding-block: 180px'>
                <h1>
                <div style='font-size: 180px; font-weight: 700'>404</div>
                <div style='font-size: 24px; font-weight: 700'>Unknown site</div>
                </h1>
                <p style="font-size: 16px; font-weight: 400">The page could not be loaded properly.</p>
            </div>
            </body>
        </html>
  `

### Test Case 4: HTTPS Server
- **HTTPS Example:**
  ```bash
  sudo python3 synprobe.py -p 443 www.cs.stonybrook.edu
  ```
  Output: 
  `
    Port 443 [HTTPS Server]: HTTP/1.1 404 Unknown site
    Connection: close
    Content-Length: 566
    Retry-After: 0
    Server: Pantheon
    Cache-Control: no-cache, must-revalidate
    Content-Type: text/html; charset=utf-8
    X-pantheon-serious-reason: The page could not be loaded properly.
    Date: Fri, 03 May 2024 23:44:33 GMT
    X-Served-By: cache-lga21979-LGA
    X-Cache: MISS
    X-Cache-Hits: 0
    X-Timer: S1714779873.369549,VS0,VE34
    Vary: Cookie
    Age: 0
    Accept-Ranges: bytes
    Via: 1.1 varnish
  `

### Test Case 5: Generic TCP Server
- **PostgreSQL running on port 5432 Example:** 
  ```bash
  sudo python3 synprobe.py -p 5432 192.168.198.132 
  ```
  Output: `Port 5432 [Generic TCP Server]:`

### Test Case 6: Generic TLS Server
- **DNS over TLS Example:**
  ```bash
  sudo python3 synprobe.py -p 853 8.8.8.8
  ```
  Output: `Port 853 [Generic TLS Server]:`

## References

1. [Python Sockets Explained - Real Python](https://realpython.com/python-sockets/)
2. [SSL and TLS in Python - Python's ssl module documentation](https://docs.python.org/3/library/ssl.html)