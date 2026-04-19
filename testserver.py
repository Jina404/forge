from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import time

class VulnHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = urlparse(self.path).query
        params = parse_qs(query)
        
        # Simulate SQL error if payload contains "'"
        if "'" in query:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"SQL syntax error: unclosed quotation mark near '1'='1'")
            return
            
        # Simulate XSS reflection
        if "<script>" in query:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<html>You searched for: " + query.encode() + b"</html>")
            return
            
        # Simulate path traversal success
        if "../" in query:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin")
            return
            
        # Normal response
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"OK")

HTTPServer(('localhost', 3000), VulnHandler).serve_forever()
