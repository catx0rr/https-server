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
certfile = '/opt/https-server/self-signed/fullchain.pem'
```

---

### Done
