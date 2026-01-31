# SSL/HTTPS Setup Guide

This guide explains how to enable HTTPS for the SOC Dashboard backend server to ensure secure encrypted communication.

## ⚠️ Security Warning

**NEVER use HTTP in production!** All data transmitted over HTTP is unencrypted and can be intercepted by attackers. This includes:
- User credentials (usernames, passwords)
- Session tokens
- Security alerts and sensitive data
- API keys and authentication tokens

## Quick Start

### Development (Self-Signed Certificates)

For **development and testing only**, you can use self-signed certificates:

#### Option 1: Using OpenSSL (Recommended)

```bash
# Navigate to the Backend directory
cd Backend

# Create certs directory
mkdir -p certs

# Generate self-signed certificate (valid for 365 days)
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout certs/server.key \
  -out certs/server.cert \
  -days 365 \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

#### Option 2: Using Node.js

```bash
# Install mkcert (easier for local development)
# macOS
brew install mkcert

# Linux
sudo apt install mkcert  # Debian/Ubuntu
sudo yum install mkcert  # CentOS/RHEL

# Windows (using Chocolatey)
choco install mkcert

# Create local CA
mkcert -install

# Generate certificates
cd Backend
mkdir -p certs
mkcert -key-file certs/server.key -cert-file certs/server.cert localhost 127.0.0.1 ::1
```

#### Enable HTTPS in Development

Update your `.env` file:

```bash
NODE_ENV=development
ENABLE_HTTPS=true
SSL_KEY_PATH=./certs/server.key
SSL_CERT_PATH=./certs/server.cert
```

Start the server:

```bash
npm run dev
```

You should see:
```
🔒 HTTPS Server is running securely at https://localhost:5000
```

⚠️ **Note**: Self-signed certificates will show browser warnings. This is normal for development.

---

## Production (Trusted SSL Certificates)

For **production environments**, you MUST use certificates from a trusted Certificate Authority (CA).

### Option 1: Let's Encrypt (FREE - Recommended)

Let's Encrypt provides free, automated SSL certificates trusted by all browsers.

#### Using Certbot

```bash
# Install Certbot
# Ubuntu/Debian
sudo apt update
sudo apt install certbot

# CentOS/RHEL
sudo yum install certbot

# Obtain certificate (replace with your domain)
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Certificates will be saved to:
# /etc/letsencrypt/live/yourdomain.com/privkey.pem    (private key)
# /etc/letsencrypt/live/yourdomain.com/fullchain.pem  (certificate + chain)
```

Update your `.env` file:

```bash
NODE_ENV=production
ENABLE_HTTPS=true
SSL_KEY_PATH=/etc/letsencrypt/live/yourdomain.com/privkey.pem
SSL_CERT_PATH=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
```

#### Auto-Renewal Setup

Let's Encrypt certificates expire after 90 days. Set up auto-renewal:

```bash
# Test renewal
sudo certbot renew --dry-run

# Set up automatic renewal (cron job)
sudo crontab -e

# Add this line to renew certificates twice daily
0 0,12 * * * certbot renew --quiet --post-hook "systemctl restart soc-dashboard"
```

### Option 2: Commercial SSL Certificates

If you purchased SSL certificates from a commercial CA (DigiCert, Sectigo, GlobalSign, etc.):

1. **Obtain your certificates** from your CA provider
2. **Place certificates** in a secure location:
   ```bash
   sudo mkdir -p /etc/ssl/soc-dashboard
   sudo cp your-private-key.key /etc/ssl/soc-dashboard/server.key
   sudo cp your-certificate.crt /etc/ssl/soc-dashboard/server.cert
   sudo cp ca-bundle.crt /etc/ssl/soc-dashboard/ca-bundle.crt

   # Set secure permissions
   sudo chmod 600 /etc/ssl/soc-dashboard/server.key
   sudo chmod 644 /etc/ssl/soc-dashboard/server.cert
   sudo chmod 644 /etc/ssl/soc-dashboard/ca-bundle.crt
   ```

3. **Update `.env` file**:
   ```bash
   NODE_ENV=production
   ENABLE_HTTPS=true
   SSL_KEY_PATH=/etc/ssl/soc-dashboard/server.key
   SSL_CERT_PATH=/etc/ssl/soc-dashboard/server.cert
   SSL_CA_PATH=/etc/ssl/soc-dashboard/ca-bundle.crt
   ```

---

## Configuration Reference

### Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `ENABLE_HTTPS` | Yes | Enable HTTPS server | `true` or `false` |
| `SSL_KEY_PATH` | If HTTPS enabled | Path to private key file | `./certs/server.key` |
| `SSL_CERT_PATH` | If HTTPS enabled | Path to certificate file | `./certs/server.cert` |
| `SSL_CA_PATH` | Optional | Path to CA bundle (chain) | `./certs/ca-bundle.crt` |
| `NODE_ENV` | Yes | Environment mode | `development` or `production` |
| `PORT` | No | Server port (default: 5000) | `443` for standard HTTPS |

### Port Recommendations

- **Development**: Use port `5000` or `3000` (no special privileges needed)
- **Production**: Use port `443` (requires root/sudo or capability grants)

To run on port 443 without root:

```bash
# Grant capability to Node.js binary (Linux)
sudo setcap cap_net_bind_service=+ep $(which node)
```

Or use a reverse proxy (recommended):

```bash
# Use Nginx or Apache as reverse proxy
# Nginx listens on 443, forwards to Node.js on 5000
```

---

## Nginx Reverse Proxy (Production Best Practice)

Instead of running Node.js on port 443, use Nginx as a reverse proxy:

### Install Nginx

```bash
sudo apt update
sudo apt install nginx
```

### Configure Nginx

Create `/etc/nginx/sites-available/soc-dashboard`:

```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # Strong SSL Security
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # HSTS (HTTP Strict Transport Security)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # Proxy to Node.js backend
    location / {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

Enable the configuration:

```bash
sudo ln -s /etc/nginx/sites-available/soc-dashboard /etc/nginx/sites-enabled/
sudo nginx -t  # Test configuration
sudo systemctl restart nginx
```

In this setup, keep your `.env` as:

```bash
NODE_ENV=production
ENABLE_HTTPS=false  # Nginx handles SSL
PORT=5000
```

---

## Troubleshooting

### Certificate Not Found Error

```
❌ SSL certificate files not found!
   Expected key: ./certs/server.key
   Expected cert: ./certs/server.cert
```

**Solution**: Ensure certificate files exist at the specified paths.

```bash
ls -la Backend/certs/
```

### Permission Denied

```
Error: EACCES: permission denied, open '/etc/letsencrypt/...'
```

**Solution**: Grant Node.js process read permissions:

```bash
# Option 1: Run with sudo (NOT recommended)
sudo npm start

# Option 2: Copy certificates to accessible location
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem ~/soc-dashboard/certs/
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem ~/soc-dashboard/certs/
sudo chown $USER:$USER ~/soc-dashboard/certs/*

# Option 3: Use deployment hook to copy certs after renewal
```

### Browser Shows "Not Secure" Warning

For **development (self-signed certificates)**: This is expected. You can:
- Click "Advanced" → "Proceed to localhost (unsafe)"
- Use mkcert which installs a local CA
- Trust the certificate manually in your browser

For **production**: This means:
- Certificate expired
- Certificate doesn't match domain
- Certificate not from trusted CA

**Solution**: Use Let's Encrypt or commercial CA certificates.

### Port 443 Already in Use

```
Error: listen EADDRINUSE: address already in use :::443
```

**Solution**: Another service (Apache, Nginx) is using port 443.

```bash
# Check what's using port 443
sudo netstat -tulpn | grep :443

# Use different port or stop conflicting service
sudo systemctl stop nginx
```

---

## Security Best Practices

1. ✅ **Always use HTTPS in production**
2. ✅ **Use strong SSL protocols** (TLSv1.2+, TLSv1.3)
3. ✅ **Keep certificates up to date** (auto-renewal for Let's Encrypt)
4. ✅ **Never commit private keys** to Git (`.gitignore` includes `certs/`)
5. ✅ **Set proper file permissions** (`chmod 600` for `.key` files)
6. ✅ **Use trusted CA certificates** in production
7. ✅ **Enable HSTS headers** (force HTTPS)
8. ✅ **Redirect HTTP to HTTPS** (no mixed content)
9. ✅ **Monitor certificate expiration** (set up alerts)
10. ✅ **Use reverse proxy** (Nginx/Apache) for additional security

---

## Quick Commands Reference

```bash
# Generate self-signed certificate (development)
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout certs/server.key -out certs/server.cert -days 365 \
  -subj "/C=US/ST=State/L=City/O=Org/CN=localhost"

# Verify certificate
openssl x509 -in certs/server.cert -text -noout

# Check certificate expiration
openssl x509 -in certs/server.cert -noout -dates

# Test HTTPS connection
curl -k https://localhost:5000/api/health

# Check certificate chain
openssl s_client -connect yourdomain.com:443 -showcerts
```

---

## Support

For additional help:
- Let's Encrypt Docs: https://letsencrypt.org/docs/
- OpenSSL Docs: https://www.openssl.org/docs/
- Node.js HTTPS: https://nodejs.org/api/https.html

---

**Last Updated**: 2025-10-21
