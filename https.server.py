#!/usr/bin/python3

import http.server
import os
import ssl
import socketserver
import argparse
from urllib.parse import urlparse, parse_qs

# Argument parsing with argparse
parser = argparse.ArgumentParser(description="Run an HTTPS server with file upload/download capabilities.")
parser.add_argument("-p", "--port", type=int, default=8080, help="Port to run the server on.")
parser.add_argument("-a", "--address", type=str, default="0.0.0.0", help="Address to bind the server.")
parser.add_argument("-c", "--certfile", type=str, default="/etc/ssl/certs/fullchain.pem", help="Path to the SSL certificate file.")
parser.add_argument("-u", "--uploads", type=str, default="/tmp", help="Directory to save uploaded files.")
parser.add_argument("-d", "--downloads", type=str, default="/tmp", help="Directory to serve downloads.")
parser.add_argument("-s", "--serve", type=str, default="/var/www/html", help="Document root directory.")
args = parser.parse_args()

# Ensure directories exist
os.makedirs(args.uploads, exist_ok=True)
os.makedirs(args.downloads, exist_ok=True)

# Custom handler to manage different endpoints
class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve document root at root URL
        if self.path == '/':
            self.path = '/index.html'
            self.directory = args.serve
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

        # Serve the /downloads directory listing
        elif self.path == '/downloads':
            self.directory = args.downloads
            self.path = '/'  # Ensure it loads the directory root within downloads
            return super().do_GET()

        # Handle other GET requests normally
        else:
            super().do_GET()

    def do_POST(self):
        # Handle file uploads at /uploads
        if self.path == '/uploads':
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
    httpd.serve_forever()
