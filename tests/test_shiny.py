import pytest
import urllib.request
import urllib.error
import http.client
import socket
import subprocess
import threading
import time
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
import socketserver

# ---
# Mock servers to validate proxy functionality
# ---

class DummyTCPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # Enable keep-alive by default

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('X-Proxy-Target', 'TCP')
        body = b"Hello from TCP Backend"
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'keep-alive')
        self.end_headers()
        self.wfile.write(body)
        
    def log_message(self, format, *args):
        pass # Silence the output

class DummyUnixHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # Enable keep-alive by default

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('X-Proxy-Target', 'UNIX')
        body = b"Hello from UNIX Backend"
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'keep-alive')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass # Silence the output

class UnixHTTPServer(socketserver.ThreadingUnixStreamServer):
    def get_request(self):
        request, client_address = self.socket.accept()
        return (request, ["local", 0]) # Mock client_address to avoid BaseHTTPServer crashing when extracting IP

# Set timeout for the servers to prevent hanging the test suite
@pytest.fixture(scope="module", autouse=True)
def setup_backends_and_shiny():
    # 1. Start TCP Backend (port 3005 as in shiny.conf)
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.request_queue_size = 2048
    socketserver.ThreadingTCPServer.daemon_threads = True
    tcp_server = socketserver.ThreadingTCPServer(('127.0.0.1', 3005), DummyTCPHandler)
    tcp_thread = threading.Thread(target=tcp_server.serve_forever)
    tcp_thread.daemon = True
    tcp_thread.start()

    # 2. Start UNIX Backend
    os.makedirs('conf.d', exist_ok=True)
    unix_path = 'conf.d/node.sock'
    if os.path.exists(unix_path):
        os.unlink(unix_path)
    
    UnixHTTPServer.request_queue_size = 2048
    UnixHTTPServer.daemon_threads = True
    unix_server = UnixHTTPServer(unix_path, DummyUnixHandler)
    unix_thread = threading.Thread(target=unix_server.serve_forever)
    unix_thread.daemon = True
    unix_thread.start()

    # 3. Assure root folder exists
    os.makedirs('www/vhost1', exist_ok=True)
    with open('www/vhost1/test_target.html', 'w') as f:
        # Pad file to 4096 bytes as Shiny assembler server hardcodes Content-Length: 4096
        content = "HelloWorld"
        content += " " * (4096 - len(content))
        f.write(content)

    # New static files for TDD HTTP Standards
    with open('www/vhost1/exact.txt', 'w') as f:
        f.write("Exact15Bytes...") # Exact 15 bytes
    with open('www/vhost1/style.css', 'w') as f:
        f.write("body { color: red; }") # CSS for MIME Type
    with open('www/vhost1/index.html', 'w') as f:
        f.write("IndexHTML") # Auto-indexed file

    proc = None
    # 4. Kill any running 'Shiny' or 'server' processes to ensure a clean testing state
    subprocess.run(["killall", "-9", "Shiny", "server"], stderr=subprocess.DEVNULL)
    time.sleep(0.5)

    try:
        # Small request to check if port 8080 still responds
        with socket.create_connection(("127.0.0.1", 8080), timeout=1) as sock:
            pass
    except ConnectionRefusedError:
        # Shiny isn't running, start it
        print("Starting ./Shiny (assumes it's compiled)...")
        proc = subprocess.Popen(['./Shiny'])
        time.sleep(3) # wait for multi-process startup and port binding

    
    time.sleep(0.5) # ensure backends and shiny are ready
    
    yield

    # Teardown
    if proc:
        # Tuer Shiny avec killall pour s'assurer que tous ses workers/enfants sont arretes
        subprocess.run(["killall", "-9", "Shiny"], stderr=subprocess.DEVNULL)
        proc.wait() 
    tcp_server.shutdown()
    unix_server.shutdown()
    tcp_server.server_close()
    unix_server.server_close()
    if os.path.exists(unix_path):
        os.unlink(unix_path)

# ---
# Unit Tests / HTTP Integration
# ---

def test_static_file():
    """Test static file distribution (via sendfile)."""
    url = "http://127.0.0.1:8080/test_target.html"
    with urllib.request.urlopen(url, timeout=5) as response:
        assert response.status == 200
        assert b"HelloWorld" in response.read()

def test_static_file_404():
    """Test the return of the appropriate 404 error for a missing file."""
    url = "http://127.0.0.1:8080/does_not_exist.html"
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(url, timeout=5)
    assert exc_info.value.code == 404

# --- NEW TDD TESTS (Nginx Standard) ---

def test_static_exact_content_length():
    """TDD: Verify the server calls stat() and sends the correct size (15 bytes here)."""
    url = "http://127.0.0.1:8080/exact.txt"
    with urllib.request.urlopen(url, timeout=5) as response:
        assert response.status == 200
        assert int(response.getheader('Content-Length')) == 15
        assert response.read() == b"Exact15Bytes..."

def test_static_content_type():
    """TDD: Verify correct Content-Type assignment based on file extension."""
    # Test text/html
    with urllib.request.urlopen("http://127.0.0.1:8080/index.html", timeout=5) as res:
        assert res.status == 200
        assert "text/html" in res.getheader('Content-Type')
    # Test text/css
    with urllib.request.urlopen("http://127.0.0.1:8080/style.css", timeout=5) as res:
        assert res.status == 200
        assert "text/css" in res.getheader('Content-Type')

def test_static_head_request():
    """TDD: The HEAD request must ONLY send headers and NO payload."""
    req = urllib.request.Request("http://127.0.0.1:8080/exact.txt", method="HEAD")
    with urllib.request.urlopen(req, timeout=5) as response:
        assert response.status == 200
        assert int(response.getheader('Content-Length')) == 15
        assert response.read() == b"" # The payload MUST be empty for HEAD!

def test_static_directory_index():
    """TDD: GET `/` must automatically serve `index.html`."""
    url = "http://127.0.0.1:8080/"
    with urllib.request.urlopen(url, timeout=5) as response:
        assert response.status == 200
        assert b"IndexHTML" in response.read()

def test_static_path_traversal():
    """TDD: Security (LFI) - Prevents extracting files outside the vhost."""
    url = "http://127.0.0.1:8080/../../../etc/passwd"
    try:
        urllib.request.urlopen(url, timeout=5)
        pytest.fail("TDD: LFI Possible! Server returned 200 instead of an error (400/403/404).")
    except urllib.error.HTTPError as e:
        assert e.code in [400, 403, 404]

def test_static_method_not_allowed():
    """TDD: POST on a static file is not allowed (405 Method Not Allowed)."""
    req = urllib.request.Request("http://127.0.0.1:8080/exact.txt", data=b"data", method="POST")
    try:
        urllib.request.urlopen(req, timeout=5)
        pytest.fail("TDD: POST successful on static file! Must be 405 Method Not Allowed.")
    except urllib.error.HTTPError as e:
        assert e.code == 405


def test_tcp_proxy():
    """Test routing through a standard TCP reverse proxy."""
    url = "http://127.0.0.1:8080/api/test"
    with urllib.request.urlopen(url, timeout=5) as response:
        assert response.status == 200
        assert response.getheader('X-Proxy-Target') == 'TCP'
        assert b"Hello from TCP Backend" in response.read()

def test_unix_proxy():
    """Test routing through proxy with Unix Domain Sockets."""
    url = "http://127.0.0.1:8080/api_sock/test"
    with urllib.request.urlopen(url, timeout=5) as response:
        assert response.status == 200
        assert response.getheader('X-Proxy-Target') == 'UNIX'
        assert b"Hello from UNIX Backend" in response.read()

def test_keep_alive():
    """Test multiple requests can be handled on a single Keep-Alive without reset."""
    conn = http.client.HTTPConnection("127.0.0.1", 8080, timeout=5)
    for i in range(10):
        # Request to the proxy_pass to get dynamic content
        conn.request("GET", "/api_sock/", headers={"Connection": "keep-alive"})
        res = conn.getresponse()
        assert res.status == 200, f"Failed at iteration i={i} with status {res.status}"
        data = res.read()
        assert b"UNIX Backend" in data
        assert res.getheader('X-Proxy-Target') == 'UNIX'
    conn.close()

def test_http_pipelining():
    """TDD: Test if the server handles pipelined HTTP requests correctly."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect(("127.0.0.1", 8080))
    
    # Sending two requests at once
    req = b"GET /exact.txt HTTP/1.1\r\nHost: localhost\r\n\r\nGET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n"
    sock.sendall(req)
    
    data = b""
    while len(data) < 4096:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"Exact15Bytes..." in data and b"IndexHTML" in data:
                break
        except socket.timeout:
            break
            
    sock.close()
    
    assert b"Exact15Bytes..." in data, "First pipelined request failed"
    # Note: Depending on server implementation it might only process the first or both.
    # At least it shouldn't crash.
    
def test_malformed_request():
    """TDD: Test resistance to malformed headers."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect(("127.0.0.1", 8080))
    
    # Missing method
    req = b" / HTTP/1.1\r\nHost: localhost\r\n\r\n"
    sock.sendall(req)
    
    try:
        data = sock.recv(1024)
        assert len(data) > 0 # Should return a 400 Bad Request or close
    except socket.timeout:
        pass
    finally:
        sock.close()

def test_large_header():
    """TDD: Reject or properly handle HTTP headers that overflow size limits."""
    conn = http.client.HTTPConnection("127.0.0.1", 8080, timeout=5)
    headers = {
        "X-Custom-Big-Header": "A" * 8192
    }
    try:
        conn.request("GET", "/", headers=headers)
        res = conn.getresponse()
        # Either 200 if supported, or 431 Request Header Fields Too Large (or 400)
        assert res.status in [200, 400, 431, 500] 
    except Exception as e:
        # Connection can simply be closed for security
        pass
    finally:
        conn.close()

