# Deployment Guide

This guide covers publishing `.well-known/schemapin.json` endpoints in production for public key discovery.

---

## Architecture

```
Internet                         Your Infrastructure
─────────                        ──────────────────

AI Clients ──HTTPS──> Web Server ──> /.well-known/schemapin.json
                                 └── /.well-known/schemapin-revocations.json
```

SchemaPin discovery is a static JSON file served over HTTPS. No application server is needed.

---

## Quick Setup

### 1. Generate Keys

```bash
# Using Python CLI
schemapin-keygen --output-dir ./keys
# Generates: private.pem, public.pem

# Using Go CLI
schemapin-keygen -out ./keys
```

### 2. Create Discovery Document

```python
from schemapin.utils import create_well_known_response
from schemapin.crypto import KeyManager

public_key_pem = open("./keys/public.pem").read()

response = create_well_known_response(
    public_key_pem=public_key_pem,
    developer_name="Acme Corp",
    schema_version="1.3",
    revocation_endpoint="https://example.com/.well-known/schemapin-revocations.json",
)

import json
with open("schemapin.json", "w") as f:
    json.dump(response, f, indent=2)
```

The resulting document:

```json
{
  "schema_version": "1.3",
  "developer_name": "Acme Corp",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----",
  "revoked_keys": [],
  "contact": "security@example.com",
  "revocation_endpoint": "https://example.com/.well-known/schemapin-revocations.json"
}
```

### 3. Create Revocation Document

```json
{
  "schema_version": "1.3",
  "developer_name": "Acme Corp",
  "revoked_keys": [],
  "revoked_schemas": [],
  "updated_at": "2026-02-15T00:00:00Z"
}
```

### 4. Deploy to Web Server

Place both files at the `.well-known` path:

```
/var/www/example.com/.well-known/
├── schemapin.json
└── schemapin-revocations.json
```

---

## Web Server Configuration

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # SchemaPin discovery
    location = /.well-known/schemapin.json {
        root /var/www/example.com;
        default_type application/json;
        add_header Cache-Control "public, max-age=3600";
        add_header Access-Control-Allow-Origin "*";
        add_header X-Content-Type-Options "nosniff";
    }

    # SchemaPin revocations
    location = /.well-known/schemapin-revocations.json {
        root /var/www/example.com;
        default_type application/json;
        add_header Cache-Control "public, max-age=300";
        add_header Access-Control-Allow-Origin "*";
        add_header X-Content-Type-Options "nosniff";
    }
}
```

### Apache

```apache
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/example.com

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/example.com.pem
    SSLCertificateKeyFile /etc/ssl/private/example.com.key

    <Location "/.well-known/schemapin.json">
        Header set Cache-Control "public, max-age=3600"
        Header set Content-Type "application/json"
        Header set Access-Control-Allow-Origin "*"
    </Location>

    <Location "/.well-known/schemapin-revocations.json">
        Header set Cache-Control "public, max-age=300"
        Header set Content-Type "application/json"
        Header set Access-Control-Allow-Origin "*"
    </Location>
</VirtualHost>
```

### Caddy

```caddyfile
example.com {
    handle /.well-known/schemapin.json {
        root * /var/www/example.com
        file_server
        header Cache-Control "public, max-age=3600"
        header Content-Type "application/json"
        header Access-Control-Allow-Origin "*"
    }

    handle /.well-known/schemapin-revocations.json {
        root * /var/www/example.com
        file_server
        header Cache-Control "public, max-age=300"
        header Content-Type "application/json"
        header Access-Control-Allow-Origin "*"
    }
}
```

---

## GitHub Pages

For open-source projects, serve discovery from GitHub Pages:

1. Create `.well-known/schemapin.json` in your repo root or docs branch
2. Ensure GitHub Pages includes `.well-known` files (may need a `_config.yml` tweak):

```yaml
# _config.yml (Jekyll)
include:
  - .well-known
```

Or use a custom domain with GitHub Pages for a clean URL.

---

## Using the SchemaPin Server

SchemaPin includes a production-ready Python server for `.well-known` endpoints:

```bash
cd server
pip install -r requirements.txt
python app.py --port 8080 --discovery /path/to/schemapin.json
```

This serves:
- `GET /.well-known/schemapin.json`
- `GET /.well-known/schemapin-revocations.json`
- `GET /health`

---

## Verification Endpoint

You can also verify your deployment at [schemapin.org/verify.html](https://schemapin.org/verify.html):

```
https://schemapin.org/verify.html?domain=example.com
```

This checks:
- Discovery document is accessible
- Public key is valid PEM format
- Key is ECDSA P-256
- Key fingerprint is computed

---

## CORS Headers

Clients may fetch discovery documents from browsers. Include CORS headers:

```
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET
```

---

## Cache Strategy

| Document | Cache-Control | Rationale |
|----------|---------------|-----------|
| Discovery | `max-age=3600` (1 hour) | Keys change infrequently |
| Discovery (rotation) | `max-age=300` (5 min) | Faster propagation |
| Revocations | `max-age=300` (5 min) | Revocations need fast propagation |

---

## Key Rotation

When rotating keys:

1. Generate a new key pair
2. Update the discovery document with the new public key
3. Add the old key's SHA-256 fingerprint to `revoked_keys`
4. Reduce cache TTL temporarily
5. Re-sign all published schemas with the new key
6. Sign skill directories with the new key

```python
from schemapin.crypto import KeyManager

# 1. Generate new key
new_private, new_public = KeyManager.generate_keypair()
new_pem = KeyManager.export_public_key_pem(new_public)

# 2. Update discovery document
import json
doc = json.load(open(".well-known/schemapin.json"))
doc["public_key_pem"] = new_pem

# 3. Revoke old key (add fingerprint to revoked_keys)
import hashlib
old_pem = doc.get("_previous_key_pem", "")
if old_pem:
    fingerprint = "sha256:" + hashlib.sha256(old_pem.encode()).hexdigest()
    doc["revoked_keys"].append(fingerprint)

with open(".well-known/schemapin.json", "w") as f:
    json.dump(doc, f, indent=2)
```

---

## Monitoring

### Health Check Script

```bash
#!/bin/bash
DOMAIN="${1:-example.com}"

echo "Checking SchemaPin endpoint..."
RESPONSE=$(curl -sf "https://$DOMAIN/.well-known/schemapin.json")
if [ $? -ne 0 ]; then
    echo "FAIL: Cannot fetch discovery document"
    exit 1
fi

# Validate public key present
PEM=$(echo "$RESPONSE" | jq -r '.public_key_pem')
if [[ "$PEM" != "-----BEGIN PUBLIC KEY-----"* ]]; then
    echo "FAIL: Invalid public key PEM"
    exit 1
fi

echo "OK: SchemaPin discovery document valid"
echo "Developer: $(echo "$RESPONSE" | jq -r '.developer_name')"
echo "Version: $(echo "$RESPONSE" | jq -r '.schema_version')"
```

### Uptime Monitoring

Add your `.well-known` URL to your uptime monitoring service:

```
https://example.com/.well-known/schemapin.json
Expected: HTTP 200, Content-Type: application/json
```
