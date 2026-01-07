Overview
--------
This program is a simple HTTP client called WebTester.py.
It takes a URL as input, connects to the server, sends an HTTP request,
and prints out the response. It also checks if the server supports HTTP/2
using TLS/ALPN.

The output includes:
- the request that was sent
- the response header
- the beginning of the response body (truncated)
- a short summary: HTTP/2 support, cookies, and whether the site is password protected

Environment
-----------
- Tested on the University of Victoria Linux server
- Default Python version on the server: Python 2.7.18
- This program requires Python 3
- Please run the program using "python3", not "python"

Requirements
------------
- Python 3 (tested on Python 2.7.18)
- Standard libraries only:
  socket, ssl, sys, urllib.parse

How to Run
----------
On the UVic server, use:
    python3 WebTester.py <url>

Examples:
    python3 WebTester.py www.google.com
    python3 WebTester.py https://www.uvic.ca/

If no scheme is given, the program assumes https:// by default.

Example Output
--------------
---Request begin---
GET https://www.google.com/ HTTP/2 
Host: www.google.com
Connection: Keep-Alive

---Request end--
HTTP request sent, awaiting response...

---Response header---
HTTP/1.1 200 OK
Date: Tue, 30 Sep 2025 02:46:23 GMT
Content-Type: text/html; charset=ISO-8859-1
Set-Cookie: AEC=...
Set-Cookie: NID=...
Connection: close

---Response body---
<!doctype html><html ... (truncated)

---Summary---
website: www.google.com
1. Supports http2: yes
2. List of Cookies:
   cookie name: AEC, domain: .google.com, expires: Sun, 29-Mar-2026
   cookie name: NID, domain: .google.com, expires: Wed, 01-Apr-2026
3. Password-protected: no

Notes
-----
- If ALPN returns None, it means the server defaults to HTTP/1.1.
- The program follows up to 5 redirects (301/302).
- Only the first 500 characters of the body are printed.
- If the hostname is invalid, the program will exit with an error message.
