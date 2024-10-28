#!/usr/bin/python3

import http.server
import os
import ssl
import socketserver
import argparse
from urllib.parse import urlparse, parse_qs
from setproctitle import setproctitle
import base64

# Argument parsing with argparse
parser = argparse.ArgumentParser(description="Run an HTTPS server with file upload/download capabilities.")
parser.add_argument("-p", "--port", type=int, default=8080, help="Port to run the server on.")
parser.add_argument("-a", "--address", type=str, default="0.0.0.0", help="Address to bind the server.")
parser.add_argument("-c", "--certfile", type=str, default="/etc/ssl/certs/fullchain.pem", help="Path to the SSL certificate file.")
parser.add_argument("-u", "--uploads", type=str, default="/tmp", help="Directory to save uploaded files.")
parser.add_argument("-d", "--downloads", type=str, default="/tmp", help="Directory to serve downloads.")
parser.add_argument("-s", "--serve", type=str, default="/var/www/html", help="Document root directory.")
parser.add_argument("-b", "--basic-auth", nargs=2, metavar=("USERNAME", "PASSWORD"), help="Enable basic auth with a username and password for /uploads and /downloads.")

args = parser.parse_args()

# Ensure directories exist
os.makedirs(args.uploads, exist_ok=True)
os.makedirs(args.downloads, exist_ok=True)

# Encode username and password for basic authentication
if args.basic_auth:
    auth_username, auth_password = args.basic_auth
    basic_auth_encoded = base64.b64encode(f"{auth_username}:{auth_password}".encode()).decode()

# Custom handler to manage different endpoints
class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Check for Basic Auth on /uploads and /downloads
        if (self.path.startswith('/uploads') or self.path.startswith('/downloads')) and args.basic_auth:
            if not self.check_basic_auth():
                self.send_auth_prompt()
                return

        # Serve document root at root URL
        if self.path == '/':
            self.path = '/index.html'
            self.directory = args.serve
            return super().do_GET()

        # Serve the /downloads directory listing
        elif self.path.startswith('/downloads'):
            self.directory = args.downloads
            requested_path = os.path.join(args.downloads, os.path.relpath(self.path, '/downloads'))
            if os.path.isdir(requested_path):
                self.list_directory(requested_path)
            else:
                self.path = '/' + os.path.relpath(requested_path, args.downloads)
                return super().do_GET()

        # Serve the file upload form at /uploads
        elif self.path == '/uploads':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
                <html>
                    <head><title>Upload Files</title></head>
                    <body>
                        <h2>Upload Files</h2>
                        <form enctype="multipart/form-data" method="post">
                            <div style="border: 1px dotted #999; padding: 20px;">
                                <input type="file" name="file" required>
                                <button type="submit">Upload File</button>
                            </div>
                        </form>
                    </body>
                </html>
            """)

        # Handle other GET requests normally
        else:
            super().do_GET()

    def do_POST(self):
        # Handle file uploads at /uploads, with optional Basic Auth
        if self.path == '/uploads':
            if args.basic_auth and not self.check_basic_auth():
                self.send_auth_prompt()
                return

            content_type = self.headers.get('Content-Type')
            if not content_type or 'multipart/form-data' not in content_type:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"400 Bad Request: Expected multipart form data.")
                return

            length = int(self.headers['Content-Length'])
            data = self.rfile.read(length)

            # Extract file data from the POST request
            boundary = content_type.split("boundary=")[-1].encode()
            parts = data.split(b'--' + boundary)

            for part in parts:
                if b'Content-Disposition:' in part:
                    # Get filename
                    filename_start = part.find(b'filename="') + 10
                    filename_end = part.find(b'"', filename_start)
                    filename = part[filename_start:filename_end].decode()

                    # Write file content to the upload directory
                    file_data_start = part.find(b'\r\n\r\n') + 4
                    file_data_end = part.rfind(b'\r\n')
                    file_data = part[file_data_start:file_data_end]

                    with open(os.path.join(args.uploads, filename), 'wb') as f:
                        f.write(file_data)

                    # Send response
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"File uploaded successfully!")
                    return

            # In case no file was found in the POST data
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"400 Bad Request: No file was uploaded.")

    def check_basic_auth(self):
        """Check if the request has valid Basic Auth credentials."""
        auth_header = self.headers.get('Authorization')
        if auth_header is None:
            return False
        auth_type, auth_data = auth_header.split(" ", 1)
        if auth_type != "Basic":
            return False
        return auth_data == basic_auth_encoded

    def send_auth_prompt(self):
        """Send a 401 response prompting for Basic Auth."""
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Restricted Access"')
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"401 Unauthorized: Please provide valid credentials.")

    def list_directory(self, path):
        """Override this method to add directory listing support."""
        try:
            list_dir = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None
        list_dir.sort(key=lambda a: a.lower())
        r = []
        displaypath = os.path.relpath(path, args.downloads)

        # Start HTML for directory listing
        r.append('<!DOCTYPE html>')
        r.append('<html><head><title>Directory listing for %s</title></head>' % displaypath)
        r.append('<body><h2>Directory listing for %s</h2>' % displaypath)
        r.append('<hr><ul>')

        # List each file and directory with a link
        for name in list_dir:
            fullname = os.path.join(path, name)
            displayname = name
            linkname = '/downloads/' + os.path.relpath(fullname, args.downloads)

            if os.path.isdir(fullname):
                displayname = name + "/"
                linkname = linkname + "/"
            r.append('<li><a href="%s">%s</a></li>' % (linkname, displayname))

        # End HTML
        r.append('</ul><hr></body></html>')

        encoded = '\n'.join(r).encode('utf-8', 'surrogateescape')
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)
        return

# HTTPS setup
certfile = os.path.abspath(args.certfile)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile)
server_address = (args.address, args.port)

# Use custom handler
handler = CustomHTTPRequestHandler

with socketserver.TCPServer(server_address, handler) as httpd:
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print(f'Serving HTTPS on {args.address} port {args.port} (https://{args.address}:{args.port}/) ...')
    print(f'Upload directory: {args.uploads}')
    print(f'Downloads directory: {args.downloads}')
    print(f'Document root: {args.serve}')
    if args.basic_auth:
        print(f'Basic Auth enabled for /uploads and /downloads with user: {auth_username}')
    setproctitle("https-server")
    httpd.serve_forever()
