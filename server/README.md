# SchemaPin .well-known Server

Production-ready HTTP server for serving SchemaPin `.well-known/schemapin.json` endpoints with support for multiple developers, key management, and revocation lists.

## Features

- **Multiple Developer Support**: Serve keys for multiple developers/domains
- **Key Management**: Upload, rotate, and revoke keys via REST API
- **Revocation Lists**: Maintain and serve key revocation information
- **CORS Support**: Browser-compatible with configurable CORS policies
- **Rate Limiting**: Built-in protection against abuse
- **Logging & Monitoring**: Comprehensive logging and metrics endpoints
- **Docker Support**: Easy containerized deployment
- **Auto-Discovery**: Automatic setup with demo data

## Quick Start

### Local Development

1. **Install Dependencies**
```bash
pip install -r requirements.txt
```

2. **Start Server**
```bash
python well_known_server.py
```

3. **Test Endpoints**
```bash
# Health check
curl http://localhost:8000/health

# Get .well-known for specific developer
curl http://localhost:8000/.well-known/schemapin/alice.example.com.json

# List all developers
curl http://localhost:8000/api/developers
```

### Docker Deployment

1. **Build Image**
```bash
docker build -t schemapin-server .
```

2. **Run Container**
```bash
docker run -p 8000:8000 -v $(pwd)/keys:/app/keys schemapin-server
```

## API Endpoints

### .well-known Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/.well-known/schemapin/{domain}.json` | GET | Get SchemaPin data for specific domain |
| `/.well-known/schemapin.json` | GET | Get default SchemaPin data (first enabled developer) |

### Management API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/developers` | GET | List all developers |
| `/api/developers/{domain}` | GET | Get developer details |
| `/api/developers/{domain}/keys` | POST | Upload new key |
| `/api/developers/{domain}/revoke` | POST | Revoke key |
| `/api/metrics` | GET | Server metrics |

## Configuration

Server configuration is managed via [`config.json`](config.json):

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8000,
    "debug": true
  },
  "cors": {
    "allow_origins": ["*"],
    "allow_credentials": true
  },
  "developers": {
    "example.com": {
      "name": "Example Corp",
      "contact": "security@example.com",
      "enabled": true
    }
  }
}
```

### Key Configuration Options

- **server.host**: Bind address (default: 0.0.0.0)
- **server.port**: Port number (default: 8000)
- **cors.allow_origins**: Allowed CORS origins
- **storage.keys_directory**: Directory for key storage
- **logging.level**: Log level (DEBUG, INFO, WARNING, ERROR)
- **developers**: Pre-configured developer domains

## Key Management

### Adding a Developer

1. **Configure Domain** (in config.json):
```json
{
  "developers": {
    "newdev.example.com": {
      "name": "New Developer",
      "contact": "security@newdev.example.com",
      "enabled": true
    }
  }
}
```

2. **Upload Public Key**:
```bash
curl -X POST http://localhost:8000/api/developers/newdev.example.com/keys \
  -H "Content-Type: application/json" \
  -d '{
    "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
    "developer_name": "New Developer",
    "contact": "security@newdev.example.com"
  }'
```

### Key Rotation

1. **Generate New Key Pair**:
```bash
# Using SchemaPin CLI tools
python -m tools.keygen --type ecdsa --output-dir ./new_keys --developer "New Developer"
```

2. **Upload New Key**:
```bash
curl -X POST http://localhost:8000/api/developers/newdev.example.com/keys \
  -H "Content-Type: application/json" \
  -d @new_key_upload.json
```

3. **Revoke Old Key**:
```bash
curl -X POST http://localhost:8000/api/developers/newdev.example.com/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "fingerprint": "sha256:old_key_fingerprint",
    "reason": "Key rotation"
  }'
```

### Key Revocation

Revoke a compromised key immediately:

```bash
curl -X POST http://localhost:8000/api/developers/example.com/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "fingerprint": "sha256:compromised_key_fingerprint",
    "reason": "Security incident"
  }'
```

## File Structure

```
server/
├── well_known_server.py      # Main server application
├── config.json               # Server configuration
├── requirements.txt          # Python dependencies
├── Dockerfile               # Docker configuration
├── README.md                # This file
├── keys/                    # Key storage directory
│   ├── alice.example.com.json
│   ├── bob.example.com.json
│   └── charlie.example.com.json
├── logs/                    # Log files
│   └── server.log
└── backups/                 # Automatic backups
    └── keys_backup_YYYYMMDD.tar.gz
```

## Security Considerations

### Production Deployment

1. **HTTPS Only**: Always use HTTPS in production
2. **Firewall**: Restrict access to management API endpoints
3. **Authentication**: Add authentication for management endpoints
4. **Rate Limiting**: Configure appropriate rate limits
5. **Monitoring**: Set up monitoring and alerting
6. **Backups**: Regular key backup and recovery procedures

### Key Storage

- Keys are stored as JSON files in the configured directory
- File permissions should be restricted (600 or 644)
- Consider encrypted storage for sensitive environments
- Regular backups are essential

### Network Security

```bash
# Example nginx configuration for HTTPS termination
server {
    listen 443 ssl;
    server_name schemapin.example.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
    
    # Restrict management API
    location /api/ {
        allow 10.0.0.0/8;
        deny all;
        proxy_pass http://localhost:8000;
    }
}
```

## Monitoring & Logging

### Health Checks

```bash
# Basic health check
curl http://localhost:8000/health

# Detailed metrics
curl http://localhost:8000/api/metrics
```

### Log Analysis

```bash
# Monitor access logs
tail -f logs/server.log

# Check for errors
grep ERROR logs/server.log

# Monitor key operations
grep "Key uploaded\|Key revoked" logs/server.log
```

### Metrics

The `/api/metrics` endpoint provides:
- Total number of developers
- Enabled developers count
- Developers with active keys
- Total revoked keys
- Server uptime

## Integration with SchemaPin

### Client Configuration

Configure SchemaPin clients to use your server:

```python
# Python
from schemapin.discovery import PublicKeyDiscovery

discovery = PublicKeyDiscovery(base_url="https://your-server.com")
```

```javascript
// JavaScript
import { PublicKeyDiscovery } from 'schemapin';

const discovery = new PublicKeyDiscovery({
    baseUrl: 'https://your-server.com'
});
```

### Custom Discovery

Override discovery URLs for specific domains:

```python
# Python
discovery.domain_overrides = {
    'example.com': 'https://your-server.com/.well-known/schemapin/example.com.json'
}
```

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Check what's using port 8000
   lsof -i :8000
   
   # Use different port
   uvicorn well_known_server:app --port 8001
   ```

2. **Permission Denied (Keys Directory)**
   ```bash
   # Fix permissions
   chmod 755 keys/
   chmod 644 keys/*.json
   ```

3. **CORS Issues**
   ```bash
   # Check CORS configuration in config.json
   # Add specific origins instead of "*" for production
   ```

4. **Key Validation Errors**
   ```bash
   # Validate key format
   openssl pkey -in key.pem -pubin -text -noout
   ```

### Debug Mode

Enable debug logging:

```json
{
  "server": {
    "debug": true
  },
  "logging": {
    "level": "DEBUG"
  }
}
```

### Testing

```bash
# Test all endpoints
python -m pytest tests/

# Manual testing
curl -v http://localhost:8000/.well-known/schemapin/alice.example.com.json
```

## Performance Tuning

### Production Settings

```json
{
  "server": {
    "debug": false,
    "reload": false
  },
  "security": {
    "rate_limit": {
      "requests_per_minute": 120
    }
  }
}
```

### Scaling

For high-traffic deployments:

1. **Load Balancer**: Use nginx or similar
2. **Multiple Instances**: Run multiple server instances
3. **Caching**: Add Redis or similar for caching
4. **Database**: Consider database storage for large key sets

## Contributing

1. Follow existing code style
2. Add tests for new features
3. Update documentation
4. Test with both Python and JavaScript clients

## License

This server implementation follows the same license as the SchemaPin project.