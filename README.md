# HTTPs Server - python3 http.server ssl wrapper

--- 
A simple ssl wrapper for python http.server A self signed certificate fullchain.pem can be loaded or a certificate from certbot.
---

Installation:

```sh
git clone https://github.com/catx0rr/https-server
```

Request self signed certificate:

```
openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:2048 -keyout priv.key -out cert.crt
```

```
cat priv.key cert.crt > fullchain.pem
```

Configure the path on https.server.py

```
certfile = '/etc/ssl/certs/fullchain.pem'
```

###### Help / Usage
```
usage: https.server.py [-h] [-p PORT] [-a ADDRESS] [-c CERTFILE] [-u UPLOADS] [-d DOWNLOADS] [-s SERVE]

Run an HTTPS server with file upload/download capabilities.

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Port to run the server on.
  -a ADDRESS, --address ADDRESS
                        Address to bind the server.
  -c CERTFILE, --certfile CERTFILE
                        Path to the SSL certificate file.
  -u UPLOADS, --uploads UPLOADS
                        Directory to save uploaded files.
  -d DOWNLOADS, --downloads DOWNLOADS
                        Directory to serve downloads.
  -s SERVE, --serve SERVE
                        Document root directory.
```

---

### Done
