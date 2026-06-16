# lab-certs/

Place mkcert-generated certificates here. The nginx config expects:
  server.crt   ← certificate
  server.key   ← private key

Generate (one-time, from the repo root):

```bash
brew install mkcert
mkcert -install                                        # trust the CA system-wide
cd lab/nginx/lab-certs
mkcert -cert-file server.crt -key-file server.key \
  localhost 127.0.0.1 <YOUR_LAN_IP>
```

After generating, restart the gateway:
```bash
podman compose -f docker-compose.yml -f podman-compose.lab.yml restart gateway
```

Files in this directory are gitignored (certs contain private keys).
