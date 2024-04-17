

## mysniffer.py

## Overview

This network packet analyzer script examines network traffic to extract key information. It begins by checking for an IP layer, capturing the source and destination IP addresses along with their respective ports. Next, it identifies the packet's protocol. If it's TCP, the analyzer looks for a TLS ClientHello layer to extract the TLS version and Server Name Indication (SNI). Note that if the TCP request is on port 443, the TLSClientHello layer from Scapy can be used.  Otherwise, if the TCP request is on a port other than 443, the fields like TLS version and server name would need to be manually extracted from the payload. For HTTP packets (identified as RAW), it parses the HTTP header, determines whether the method is GET or POST, and extracts the HTTP method, hostname, and request URI.

## Requirements

Python 3.x (https://www.python.org/) \
Scapy (https://scapy.net/) - Install using `pip install scapy`

## Run from the command line:

### 1. Live Capture

`sudo python mysniffer.py -i <interface_name>`

#### Sample Requests and Outputs

#### 1. Simple GET

Request: 

`curl http://www.example.com`

Output: 

`2024-03-08 13:13:41.478643 HTTP 172.22.77.241:47228 -> 93.184.216.34:80 www.example.com GET /`

#### 2. GET with custom headers:

Request: 

`curl -H "User-Agent: MyCustomBrowser" http://www.testsite.org/page1`

Output: 

`2024-03-08 13:14:05.162630 HTTP 172.22.77.241:38806 -> 76.76.21.241:80 www.testsite.org GET /page1`

#### 3. POST with data:

Request: 

`curl -X POST -d "name=Alice&city=NewYork" http://www.example.com/submit/mydata`

Output: 

`2024-03-08 13:14:32.832689 HTTP 172.22.77.241:56740 -> 93.184.216.34:80 www.example.com POST /submit/mydata`

#### 4. HTTP GET Requests on Custom Ports

Request: 

`curl portquiz.net:3221` \
`curl http://portquiz.net:3229/api/data` 

Output:

`2024-03-08 13:14:51.678509 HTTP 172.22.77.241:42796 -> 35.180.139.74:3221 portquiz.net GET /` \
`2024-03-08 13:15:10.970904 HTTP 172.22.77.241:39134 -> 35.180.139.74:3229 portquiz.net GET /api/data`

#### 5. HTTP POST Requests to Custom Ports

Request: 

`curl -X POST -d "field1=value1&field2=value2" http://portquiz.net:5000/submit_form` \
`curl -X POST -H "Content-Type: application/json" -d '{"message": "Hello"}' http://portquiz.net:9000/send`

Output:

`2024-03-08 13:15:30.703858 HTTP 172.22.77.241:39178 -> 35.180.139.74:5000 portquiz.net POST /submit_form` \
`2024-03-08 13:15:50.013389 HTTP 172.22.77.241:59002 -> 35.180.139.74:9000 portquiz.net POST /send`

#### 6. Basic HTTPS GET

Request: 

`curl https://www.example.com`

Output:

`2024-03-08 13:16:16.772094 TLS v1.2 172.22.77.241:33172 -> 93.184.216.34:443 www.example.com`


#### 7. HTTPS with older TLS version:

Request:

`curl -X G--tlsv1.1 --tls-max 1.1 --ciphers DEFAULT@SECLEVEL=0 -vI https://www.youtube.com` 

Output:

`2024-03-08 13:17:29.865060 TLS v1.1 172.22.77.241:56816 -> 142.251.111.190:443 www.youtube.com`

#### 8. wget for HTTPS download:

Request:

`wget https://www.example.com/files/document.pdf`

Output:

`2024-03-08 13:17:45.838369 TLS v1.2 172.22.77.241:53658 -> 93.184.216.34:443 www.example.com`

#### 9. TLS Requests on Custom Ports

Request: 

`curl https://portquiz.takao-tech.com:8021/`


Output:

`2024-03-08 23:29:00.000000 TLS v1.2 172.22.77.241:34228 -> 18.134.37.119:8021 portquiz.takao-tech.com`

### 2. Trace File Analysis

`sudo python mysniffer.py -r hw1.pcap`

Output:


<div style="height: 100px; overflow-y: scroll;">
<pre>
2013-01-12 22:30:48.000000 HTTP 92.240.68.152:9485 -> 192.168.0.200:80 pic.leech.it GET http://pic.leech.it/i/f166c/479246b0asttas.jpg
2013-01-12 22:30:49.000000 HTTP 192.168.0.200:40341 -> 87.98.246.8:80 pic.leech.it:80 GET /i/f166c/479246b0asttas.jpg
2013-01-12 22:31:19.000000 HTTP 92.240.68.152:17260 -> 192.168.0.200:80 ecx.images-amazon.com GET http://ecx.images-amazon.com/images/I/41oZ1XsiOAL._SL500_AA300_.jpg
2013-01-12 22:31:19.000000 HTTP 192.168.0.200:40630 -> 216.137.63.121:80 ecx.images-amazon.com:80 GET /images/I/41oZ1XsiOAL.
2013-01-12 22:31:50.000000 HTTP 92.240.68.152:19957 -> 192.168.0.200:80 images4.byinter.net GET http://images4.byinter.net/DSC442566.gif
2013-01-12 22:31:50.000000 HTTP 192.168.0.200:55528 -> 159.148.96.184:80 images4.byinter.net:80 GET /DSC442566.gif
2013-01-12 22:32:21.000000 HTTP 92.240.68.152:22272 -> 192.168.0.200:80 www.nature.com GET http://www.nature.com/news/2009/090527/images/459492a-i1.0.jpg
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/InRelease
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/InRelease
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release.gpg
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/Release.gpg
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/Release
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/InRelease
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/main/source/Sources.bz2
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/source/Sources.bz2
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/restricted/source/Sources.bz2
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/binary-i386/Packages.bz2
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/Release.gpg
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.bz2
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/universe/i18n/Index
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.bz2
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/restricted/i18n/Translation-en.bz2
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.xz
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.xz
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/Release.gpg
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.lzma
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.lzma
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.gz
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/Release
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.gz
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:59019 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/main/source/Sources.bz2
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/restricted/i18n/Index
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/universe/binary-i386/Packages.bz2
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/restricted/source/Sources.bz2
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/multiverse/i18n/Index
2013-01-13 02:54:47.000000 HTTP 192.168.0.200:47110 -> 91.189.91.15:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/main/i18n/Translation-en.bz2
2013-01-13 05:36:10.000000 HTTP 192.168.0.200:49291 -> 46.51.197.89:80 duckduckgo.com GET /favicon.ico
2013-01-13 05:36:10.000000 HTTP 192.168.0.200:42497 -> 91.189.90.40:80 start.ubuntu.com GET /11.10/Google/?sourceid=hp
2013-01-13 05:36:15.000000 HTTP 192.168.0.200:42990 -> 62.252.170.91:80 www.nature.com GET /news/2009/090527/images/459492a-i1.0.jpg
2013-01-13 05:44:43.000000 HTTP 192.168.0.200:52724 -> 91.189.89.88:80 start.ubuntu.com GET /11.10/Google/?sourceid=hp
2013-01-13 05:44:46.000000 HTTP 192.168.0.200:43029 -> 216.137.63.137:80 ecx.images-amazon.com GET /images/I/41oZ1XsiOAL
2013-01-13 05:44:46.000000 HTTP 192.168.0.200:43029 -> 216.137.63.137:80 ecx.images-amazon.com GET /favicon.ico
2013-01-13 05:45:22.000000 HTTP 192.168.0.200:42503 -> 91.189.90.40:80 start.ubuntu.com GET /11.10/Google/?sourceid=hp
2013-01-13 05:45:26.000000 HTTP 192.168.0.200:58724 -> 159.148.96.184:80 images4.byinter.net GET /DSC442566.gif
2013-01-13 05:45:26.000000 HTTP 192.168.0.200:58724 -> 159.148.96.184:80 images4.byinter.net GET /favicon.ico
2013-01-13 05:45:26.000000 HTTP 192.168.0.200:58724 -> 159.148.96.184:80 images4.byinter.net GET /favicon.ico
2013-01-13 05:45:50.000000 HTTP 192.168.0.200:58460 -> 91.189.90.41:80 start.ubuntu.com GET /11.10/Google/?sourceid=hp
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/InRelease
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/InRelease
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/Release.gpg
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release.gpg
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/Release
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/InRelease
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/source/Sources.bz2
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/binary-i386/Packages.bz2
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/main/source/Sources.bz2
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.bz2
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/Release.gpg
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.bz2
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.xz
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/restricted/source/Sources.bz2
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.xz
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/Release.gpg
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.lzma
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/universe/i18n/Index
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.lzma
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US.gz
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/Release
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en.gz
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en_US
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/main/i18n/Translation-en.bz2
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:59034 -> 91.189.88.33:80 extras.ubuntu.com GET /ubuntu/dists/oneiric/main/i18n/Translation-en
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/Release
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/universe/i18n/Translation-en.bz2
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/Release
2013-01-14 02:52:53.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/main/source/Sources.bz2
2013-01-14 02:52:53.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/universe/i18n/Index
2013-01-14 02:52:53.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/universe/binary-i386/Packages.bz2
2013-01-14 02:52:53.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/restricted/i18n/Index
2013-01-14 02:52:54.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-updates/universe/i18n/Index
2013-01-14 02:52:54.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/main/source/Sources.bz2
2013-01-14 02:52:54.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/universe/source/Sources.bz2
2013-01-14 02:52:54.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric-backports/main/binary-i386/Packages.bz2
2013-01-14 02:52:54.000000 HTTP 192.168.0.200:54634 -> 91.189.91.14:80 us.archive.ubuntu.com GET /ubuntu/dists/oneiric/restricted/i18n/Translation-en.bz2
2013-01-14 12:47:49.000000 HTTP 1.234.31.20:38720 -> 192.168.0.200:80 86.0.33.20 GET /w00tw00t.at.blackhats.romanian.anti-sec:)
2013-01-14 12:47:54.000000 HTTP 1.234.31.20:42230 -> 192.168.0.200:80 86.0.33.20 GET /phpMyAdmin/scripts/setup.php
2013-01-14 12:48:00.000000 HTTP 1.234.31.20:45552 -> 192.168.0.200:80 86.0.33.20 GET /phpmyadmin/scripts/setup.php
2013-01-14 12:48:06.000000 HTTP 1.234.31.20:48734 -> 192.168.0.200:80 86.0.33.20 GET /pma/scripts/setup.php
2013-01-14 12:48:12.000000 HTTP 1.234.31.20:52079 -> 192.168.0.200:80 86.0.33.20 GET /myadmin/scripts/setup.php
2013-01-14 12:48:18.000000 HTTP 1.234.31.20:55672 -> 192.168.0.200:80 86.0.33.20 GET /MyAdmin/scripts/setup.php

</pre>
</div>

### 3. Optional: BPF Filter Expression

`sudo python mysniffer.py -r 'hw1.pcap' 'dst host 91.189.92.190' `

Output:

<div style="height: 100px; overflow-y: scroll;">
<pre>
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/InRelease
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release.gpg
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/main/source/Sources.bz2
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/restricted/source/Sources.bz2
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/universe/i18n/Index
2013-01-13 02:54:46.000000 HTTP 192.168.0.200:49821 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/restricted/i18n/Translation-en.bz2
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/InRelease
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release.gpg
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/Release
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/main/source/Sources.bz2
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/restricted/source/Sources.bz2
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/universe/i18n/Index
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/main/i18n/Translation-en.bz2
2013-01-14 02:52:52.000000 HTTP 192.168.0.200:49836 -> 91.189.92.190:80 security.ubuntu.com GET /ubuntu/dists/oneiric-security/universe/i18n/Translation-en.bz2
</div>
</pre>

## arpwatch.py

## Overview

This script proactively monitors Address Resolution Protocol (ARP) entries to enhance network security. It begins by reading the ARP table from the operating system's cache. If the cache is empty, it populates the table with a ground-truth ARP broadcast request. The script then uses Scapy to monitor ARP requests on the network. Any detected changes in IP-to-MAC address bindings will trigger a warning, indicating a potential network anomaly or security concern.


## Requirements

Python 3.x (https://www.python.org/) \
Scapy (https://scapy.net/) - Install using `pip install scapy` \
netaddr (https://pypi.org/project/netaddr/) - Install using `pip install netaddr`


## Run from the command line:

`sudo python3 arpwatch.py -i eth0`

## ARP poisoning Attack Setup

VM1: Kali 2023         192.168.198.1   (00:0c:29:2c:be:55)
VM2: Win 10 VM         192.168.198.130 (00:0c:29:b3:af:5e)
VMWare gateway:        192.168.198.2   (00:50:56:f4:e2:98)

`Win> ping -n 1000 8.8.8.8`

`Kali> sudo su root`
`Kali> echo 1 > /proc/sys/net/ipv4/ip_forward`
#### console 1
`Kali> arpspoof -i eth0 -t 192.168.9.130 192.168.9.2`
#### console 2
`Kali> arpspoof -i eth0 -t 192.168.9.2 192.168.9.130`
#### console 3
`Kali> tcpdump -n -e icmp   # MAC addresses differ in each pair of packets`

## Output

```
Initial ARP table:
192.168.198.254 -> 00:50:56:e0:21:92
192.168.198.2 -> 00:50:56:f4:e2:98
192.168.198.130 -> 00:0c:29:b3:af:5e
Monitoring for ARP cache changes...
ARP Cache Poisoning Alert: 192.168.198.130 changed from 00:0c:29:b3:af:5e to 00:0c:29:2c:be:55
ARP Cache Poisoning Alert: 192.168.198.2 changed from 00:50:56:f4:e2:98 to 00:0c:29:2c:be:55

```