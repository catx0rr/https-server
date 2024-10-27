#!/usr/bin/python3

import http.server, os, sys, ssl, socketserver

if len(sys.argv) != 2:
    print("Usage: ./https.server.py <port>\n\n./https.server.py 8080")
    sys.exit()
else:
    port = sys.argv[1]

address = '0.0.0.0'
port = sys.argv[1]
certfile = '/opt/tools/network-tools/https-server/self-signed/fullchain.pem'
directory = '/root/'

certfile = os.path.abspath(certfile)
directory = os.path.join(os.path.dirname(__file__), directory)
os.chdir(directory)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile)
server_address = (address, int(port))
handler = http.server.SimpleHTTPRequestHandler

with socketserver.TCPServer(server_address, handler) as httpd:
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print('Serving HTTPS on %s port %s (https://%s:%s/) ...' % (address, port, address, port)) 
    httpd.serve_forever()

