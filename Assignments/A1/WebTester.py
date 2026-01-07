import sys
import socket
import ssl
from urllib.parse import urlparse

def supports_http2_simple(url: str, timeout: float = 5.0):

    #only use ALPN on HTTPS return (bool, detail)

    u = urlparse(url)
    if not u.scheme:
        raw = u.path.split('/', 1)[0] or u.netloc or u.path
        url = f"https://{raw}/"
        u = urlparse(url)

    # must be https
    elif u.scheme == "http":
        host_only = u.hostname 
        path = u.path or "/"
        url = f"https://{host_only}{path}"
        u = urlparse(url)
    
    host = u.hostname
    # only https, no http

    port = u.port or 443

    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                proto = ssock.selected_alpn_protocol()
                if proto == "h2":
                    return (True, f"GET {url} HTTP/2 \nHost: {host}\nConnection: Keep-Alive")
                elif proto == "http/1.1":
                    return (False, f"GET {url} HTTP/1.1 \nHost: {host}\nConnection: Keep-Alive")
                else:
                    return (False, f"GET {url} \nALPN returned None (server defaults to HTTP/1.1)\nConnection: Keep-Alive")
    except Exception as e:
        return (False, f"TLS/ALPN detection failed：{e}")

def get_cookie(url: str, max_redirects=5):
    u = urlparse(url)


# if no http/https，then defalt https
    if not u.scheme:
        url = "https://" + url
        u = urlparse(url)
        

    host = u.hostname 
    path = u.path or "/"
    port = u.port or (443 if u.scheme == "https" else 80)
    try:
        socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Error: Invalid hostname {host}.")
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if u.scheme == "https":
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=host)
    sock.connect((host, port))
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: close\r\n"
        "Accept: text/html,*/*;q=0.8\r\n"
        "Accept-Encoding: identity\r\n"
        "User-Agent: WebTester/1.0\r\n"
        "\r\n"
    )
    sock.sendall(request.encode("ascii"))
    response = b""
    while True:
        data = sock.recv(4096)
        if not data:
            break
        response += data
    sock.close()
    
    text = response.decode("iso-8859-1", errors="ignore")
    
    sep = text.find("\r\n\r\n")
    header_str = text[:sep] if sep != -1 else text
    first_line = header_str.split("\r\n", 1)[0]
    parts = first_line.split()
    status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0

    # 301/302 jump
    if status in (301, 302) and max_redirects > 0:
        location = None
        for line in header_str.split("\r\n"):
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
                break
        if location:
            if location.startswith("/"):
                location = f"{u.scheme}://{host}{location}"
            elif not location.startswith("http"):
                location = f"{u.scheme}://{location}"
            # recurision max_redirects - 1
            return get_cookie(location, max_redirects - 1)

    return text

def parse_response(text: str):
    # header and body
    sep = text.find("\r\n\r\n")
    if sep == -1:
        header_str = text
        body_str = ""
    else:
        header_str = text[:sep]
        body_str = text[sep+4:]

    # status code
    first_line = header_str.split("\r\n", 1)[0]
    parts = first_line.split()
    status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    password_protected = status_code in (401, 403)

    #Set-Cookie
    cookies = []
    for line in header_str.split("\r\n"):
        if line.lower().startswith("set-cookie:"):
            v = line[len("set-cookie:"):].strip()
            parts = [p.strip() for p in v.split(";")]
            if not parts:
                continue
            name = parts[0].split("=", 1)[0].strip()
            domain = None
            expires = None
            for p in parts[1:]:
                pl = p.lower()
                if pl.startswith("domain="):
                    domain = p.split("=", 1)[1].strip()
                elif pl.startswith("expires="):
                    expires = p.split("=", 1)[1].strip()
            cookies.append((name, domain, expires))

    return {
        "status": status_code,
        "password_protected": password_protected,
        "header": header_str,
        "body": body_str,
        "cookies": cookies,
    }

def print_summary(url, supports_http2, cookies, password_protected):
    if url.startswith("http://") or url.startswith("https://"):
        host = url.split("://", 1)[1]
    else:
        host = url

    print(f"website: {host}")
    print(f"1. Supports http2: {'yes' if supports_http2 else 'no'}")

    print("2. List of Cookies:")
    if cookies:
        for name, domain, expires in cookies:
            line = f"   cookie name: {name}"
            if expires:
                line += f", expires time: {expires}"
            if domain:
                line += f", domain name: {domain}"
            print(line)
    else:
        print("   (no cookies)")

    print(f"3. Password-protected: {'yes' if password_protected else 'no'}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("python3 WebTester_http2.py <https-url>")
        sys.exit(1)
    url = sys.argv[1]
    ok, why = supports_http2_simple(url)

    print("---Request begin---")
    print(why)
    print("\n---Request end--\nHTTP request sent, awaiting response...")
    text=get_cookie(url)
    if text is None:
        print("Invalid hostname or connection failed. Please check the URL.")
        sys.exit(1)
    info = parse_response(text)

    print("\n---Response header---")
    print(info["header"])
    
    print("\n---Response body---")
    print(info["body"][:500])
    
    print("\n---Summary---")
    print_summary(url, ok, info["cookies"], info["password_protected"])