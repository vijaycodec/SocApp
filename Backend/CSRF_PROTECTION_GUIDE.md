# CSRF Protection Implementation Guide

This guide explains how to implement CSRF (Cross-Site Request Forgery) protection in the SOC Dashboard API.

## Overview

CSRF protection has been implemented using a double-submit cookie pattern with server-side validation. While the application primarily uses JWT Bearer tokens (which provide some CSRF protection), this additional layer ensures defense-in-depth security.

## How It Works

1. **Token Generation**: Server generates a cryptographically secure random token
2. **Token Storage**: Token is hashed and stored server-side with expiration
3. **Token Delivery**: Token is sent to client via HTTP header and optionally in response body
4. **Token Validation**: Client includes token in subsequent state-changing requests
5. **Token Verification**: Server validates token before processing the request

## Installation

The CSRF middleware is already created at `/Backend/middlewares/csrf.middleware.js`. No additional packages are required.

## Usage

### Option 1: Protecting Individual Routes

```javascript
import { validateCsrfToken, getCsrfToken } from './middlewares/csrf.middleware.js';

// Provide CSRF token endpoint
app.get('/api/csrf-token', getCsrfToken);

// Protect state-changing routes
app.post('/api/users', validateCsrfToken, createUser);
app.put('/api/users/:id', validateCsrfToken, updateUser);
app.delete('/api/users/:id', validateCsrfToken, deleteUser);
```

### Option 2: Protecting All Routes in a Router

```javascript
import express from 'express';
import { validateCsrfToken } from '../middlewares/csrf.middleware.js';

const router = express.Router();

// Apply CSRF validation to all routes in this router
router.use(validateCsrfToken);

router.post('/create', createItem);
router.put('/:id', updateItem);
router.delete('/:id', deleteItem);

export default router;
```

### Option 3: Global Protection with Exceptions

```javascript
import { validateCsrfToken } from './middlewares/csrf.middleware.js';

// Apply globally (but place after routes that don't need CSRF protection)
app.use('/api', (req, res, next) => {
  // Skip CSRF for specific routes
  const exemptPaths = ['/api/auth/login', '/api/auth/register', '/api/health'];

  if (exemptPaths.includes(req.path)) {
    return next();
  }

  validateCsrfToken(req, res, next);
});
```

## Client-Side Implementation

### Step 1: Fetch CSRF Token

```javascript
// Fetch CSRF token before making state-changing requests
const response = await fetch('/api/csrf-token', {
  credentials: 'include' // Important: include cookies
});

const { csrfToken } = await response.json();
```

### Step 2: Include Token in Requests

**Option A: Using Headers (Recommended)**

```javascript
await fetch('/api/users', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`,
    'X-CSRF-Token': csrfToken // Include CSRF token
  },
  credentials: 'include',
  body: JSON.stringify(userData)
});
```

**Option B: In Request Body**

```javascript
await fetch('/api/users', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`
  },
  body: JSON.stringify({
    ...userData,
    _csrf: csrfToken // Include in body
  })
});
```

### React/Next.js Example

```javascript
// Create a custom hook for CSRF-protected requests
import { useState, useEffect } from 'react';

export function useCsrfProtection() {
  const [csrfToken, setCsrfToken] = useState(null);

  useEffect(() => {
    // Fetch CSRF token on component mount
    fetch('/api/csrf-token', { credentials: 'include' })
      .then(res => res.json())
      .then(data => setCsrfToken(data.csrfToken));
  }, []);

  const protectedFetch = async (url, options = {}) => {
    if (!csrfToken) {
      throw new Error('CSRF token not available');
    }

    return fetch(url, {
      ...options,
      credentials: 'include',
      headers: {
        ...options.headers,
        'X-CSRF-Token': csrfToken,
      },
    });
  };

  return { csrfToken, protectedFetch };
}

// Usage in component
function MyComponent() {
  const { protectedFetch } = useCsrfProtection();

  const handleSubmit = async (data) => {
    const response = await protectedFetch('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });

    const result = await response.json();
    console.log(result);
  };

  return <form onSubmit={handleSubmit}>...</form>;
}
```

## Token Lifecycle

1. **Generation**: Token is generated when client requests it or after login
2. **Expiration**: Tokens expire after 15 minutes
3. **One-Time Use**: Each token can only be used once
4. **Automatic Cleanup**: Expired tokens are automatically cleaned up every 5 minutes

## Security Considerations

### ✅ What CSRF Protection Does

- Prevents unauthorized state-changing requests from malicious websites
- Ensures requests originate from your application
- Adds defense-in-depth to JWT authentication

### ⚠️ What CSRF Protection Does NOT Do

- Does NOT protect against XSS (Cross-Site Scripting) attacks
- Does NOT replace authentication/authorization
- Does NOT protect read-only operations (GET requests)

### Best Practices

1. **Always Use HTTPS in Production**
   ```javascript
   // In .env
   NODE_ENV=production
   ENABLE_HTTPS=true
   ```

2. **Set Secure Cookie Attributes**
   - `httpOnly: true` - Prevents JavaScript access
   - `secure: true` - Only send over HTTPS (production)
   - `sameSite: 'strict'` - Prevents CSRF via cookies

3. **Combine with Other Security Measures**
   - JWT authentication
   - Input validation
   - Rate limiting
   - XSS protection (Content Security Policy)

4. **Token Refresh Strategy**
   ```javascript
   // Refresh token before it expires
   setInterval(async () => {
     const res = await fetch('/api/csrf-token');
     const { csrfToken } = await res.json();
     updateToken(csrfToken);
   }, 10 * 60 * 1000); // Refresh every 10 minutes
   ```

## Production Deployment

### Using Redis for Token Storage (Recommended)

For production environments with multiple server instances, use Redis instead of in-memory storage:

```javascript
import Redis from 'redis';

const redisClient = Redis.createClient({
  url: process.env.REDIS_URL
});

await redisClient.connect();

// Store token
await redisClient.setEx(
  `csrf:${tokenHash}`,
  900, // 15 minutes in seconds
  JSON.stringify({ createdAt: Date.now(), userId: user.id })
);

// Retrieve token
const storedToken = await redisClient.get(`csrf:${tokenHash}`);

// Delete token
await redisClient.del(`csrf:${tokenHash}`);
```

## Troubleshooting

### Error: "CSRF token missing"

**Cause**: Token not included in request

**Solution**: Ensure you're sending the token in the `X-CSRF-Token` header or `_csrf` field

### Error: "Invalid CSRF token"

**Cause**: Token doesn't match or has been used already

**Solution**: Fetch a new token before retrying the request

### Error: "CSRF token expired"

**Cause**: Token is older than 15 minutes

**Solution**: Implement automatic token refresh in your client application

## Testing

### Manual Testing

```bash
# 1. Get CSRF token
curl -X GET http://localhost:5000/api/csrf-token

# 2. Use token in request
curl -X POST http://localhost:5000/api/users \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: YOUR_TOKEN_HERE" \
  -d '{"name":"John Doe"}'
```

### Automated Testing

```javascript
describe('CSRF Protection', () => {
  it('should reject requests without CSRF token', async () => {
    const response = await request(app)
      .post('/api/users')
      .send({ name: 'Test User' });

    expect(response.status).toBe(403);
    expect(response.body.message).toBe('CSRF token missing');
  });

  it('should accept requests with valid CSRF token', async () => {
    // Get token
    const tokenResponse = await request(app).get('/api/csrf-token');
    const { csrfToken } = tokenResponse.body;

    // Use token
    const response = await request(app)
      .post('/api/users')
      .set('X-CSRF-Token', csrfToken)
      .send({ name: 'Test User' });

    expect(response.status).toBe(201);
  });
});
```

## Migration Path

To gradually roll out CSRF protection:

1. **Phase 1**: Deploy CSRF middleware without enforcement
   ```javascript
   // Log but don't block
   app.use((req, res, next) => {
     const token = req.headers['x-csrf-token'];
     if (!token) {
       console.warn('CSRF token missing for:', req.path);
     }
     next();
   });
   ```

2. **Phase 2**: Enforce on critical endpoints
   ```javascript
   app.delete('/api/users/:id', validateCsrfToken, deleteUser);
   app.post('/api/admin/*', validateCsrfToken, adminRoutes);
   ```

3. **Phase 3**: Enable globally with exceptions
   ```javascript
   app.use('/api', validateCsrfToken);
   ```

## Support

For questions or issues:
- Check logs for detailed error messages
- Review the middleware code at `/Backend/middlewares/csrf.middleware.js`
- Consult OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

---

**Last Updated**: 2025-10-21
**Version**: 1.0
