# Middleware Migration Guide

This guide documents the migration from the old middleware structure to the new comprehensive middleware system for the SOC Dashboard.

## Overview of Changes

The middleware system has been completely restructured to support:
- JWT-based authentication with session management
- RBAC (Role-Based Access Control) with JSONB permissions
- Organization-scoped multi-tenancy
- Subscription-based feature access
- Comprehensive security measures
- Advanced rate limiting
- Input validation and sanitization

## File Changes

### ✅ Updated Files
- `auth.middleware.js` - Completely rewritten for JWT + session management
- `rateLimit.middleware.js` - Enhanced with multiple rate limiting strategies
- `validation.middleware.js` - Comprehensive validation with Joi schemas

### ✅ New Files
- `authorization.middleware.js` - RBAC permissions and organization scoping
- `organisationScope.middleware.js` - Multi-tenant data isolation
- `errorHandler.middleware.js` - Comprehensive error handling
- `index.js` - Centralized middleware exports
- `MIGRATION_GUIDE.md` - This file

### ⚠️ Deprecated Files (Should be removed)
- `level.middleware.js` - Replaced by `authorization.middleware.js`
- `role.middleware.js` - Replaced by `authorization.middleware.js`
- `permission.middleware.js` - Replaced by `authorization.middleware.js`
- `superadminAccess.middleware.js` - Integrated into `authorization.middleware.js`
- `validate.middleware.js` - Replaced by `validation.middleware.js`
- `dynamicTierAccess.middleware.js` - Replaced by subscription features in `authorization.middleware.js`
- `fetchClientCredentials.js` - Functionality moved to `auth.middleware.js`

## Migration Examples

### Authentication

#### Old Way:
```javascript
import { protect } from '../middlewares/auth.middleware.js';
router.use(protect);
```

#### New Way:
```javascript
import { authenticateToken } from '../middlewares/auth.middleware.js';
// or
import { authenticateToken } from '../middlewares/index.js';
router.use(authenticateToken);
```

### Permission Checking

#### Old Way:
```javascript
import hasPermission from '../middlewares/permission.middleware.js';
router.use(hasPermission('user:read'));
```

#### New Way:
```javascript
import { authorizePermissions } from '../middlewares/authorization.middleware.js';
router.use(authorizePermissions(['user:read']));
```

### Role-Based Access

#### Old Way:
```javascript
import { isSuperAdmin } from '../middlewares/role.middleware.js';
router.use(isSuperAdmin);
```

#### New Way:
```javascript
import { requireRole } from '../middlewares/authorization.middleware.js';
router.use(requireRole(['SUPER_ADMIN']));
// or use authorizePermissions - super admin bypass is automatic
router.use(authorizePermissions(['admin:access']));
```

### Level-Based Access

#### Old Way:
```javascript
import { checkLevel } from '../middlewares/level.middleware.js';
router.use(checkLevel(['admin', 'manager']));
```

#### New Way:
```javascript
import { requireRole } from '../middlewares/authorization.middleware.js';
router.use(requireRole(['ADMIN', 'MANAGER']));
```

### Rate Limiting

#### Old Way:
```javascript
import loginLimiter from '../middlewares/rateLimit.middleware.js';
router.use(loginLimiter);
```

#### New Way:
```javascript
import { authLimiters } from '../middlewares/rateLimit.middleware.js';
router.use(authLimiters.login);
// or custom rate limiting
import { rateLimiter } from '../middlewares/rateLimit.middleware.js';
router.use(rateLimiter({ max: 5, windowMs: 15 * 60 * 1000 }));
```

### Validation

#### Old Way:
```javascript
// Manual validation in routes
const validateUser = (req, res, next) => {
  if (!req.body.email) {
    return res.status(400).json({ error: 'Email required' });
  }
  next();
};
```

#### New Way:
```javascript
import { validateRequest } from '../middlewares/validation.middleware.js';
import { userValidator } from '../validators/user.validator.js';
router.use(validateRequest(userValidator.create, 'body'));
```

## Common Middleware Combinations

### Standard Protected Route
```javascript
import { standardAuth } from '../middlewares/index.js';
router.get('/protected-endpoint', ...standardAuth, controller);
```

### Admin Only Route
```javascript
import { adminAuth } from '../middlewares/index.js';
router.get('/admin-only', ...adminAuth(['admin:read']), controller);
```

### Create Endpoint with Validation
```javascript
import { createEndpoint } from '../middlewares/index.js';
import { validateRequest } from '../middlewares/validation.middleware.js';
import { userValidator } from '../validators/user.validator.js';

router.post('/users', 
  validateRequest(userValidator.create),
  ...createEndpoint(['user:create']),
  createUser
);
```

### File Upload Endpoint
```javascript
import { fileUpload } from '../middlewares/index.js';

router.post('/upload',
  ...fileUpload({
    maxSize: 10 * 1024 * 1024, // 10MB
    allowedMimeTypes: ['image/jpeg', 'image/png']
  }),
  uploadController
);
```

## Permission System Changes

### Old Permission Structure
Permissions were stored as references to Permission documents:
```javascript
role: {
  name: 'Admin',
  permissions: [ObjectId('...'), ObjectId('...')]
}
```

### New Permission Structure
Permissions are stored as JSONB with resource:action:scope format:
```javascript
role: {
  role_code: 'ADMIN',
  permissions: {
    'user:read:organisation': true,
    'user:create:organisation': true,
    'ticket:assign:organisation': true,
    'admin:*:*': true
  }
}
```

### Permission Scopes
- `own` - User's own resources only
- `organisation` - Resources within user's organisation
- `all` - All resources (super admin level)

### Wildcard Permissions
- `user:*:organisation` - All user actions within organisation
- `*:read:own` - Read access to all own resources
- `*:*:*` - Full access (super admin)

## Organization Scoping

### Automatic Organization Filtering
```javascript
import { organisationScope } from '../middlewares/index.js';

router.get('/users', 
  authenticateToken,
  organisationScope(), // Automatically filters by user's organisation
  getUsers
);
```

### Multi-Organization Access (Admin)
```javascript
import { multiOrgScope } from '../middlewares/organisationScope.middleware.js';

router.get('/admin/users',
  authenticateToken,
  authorizePermissions(['admin:read']),
  multiOrgScope(['ADMIN', 'MANAGER']), // Allow cross-org access for certain roles
  getAllUsers
);
```

## Subscription Features

### Feature Access Control
```javascript
import { requireFeature } from '../middlewares/authorization.middleware.js';

router.get('/advanced-analytics',
  authenticateToken,
  requireFeature('advanced_analytics'),
  getAdvancedAnalytics
);
```

### Subscription Limits
```javascript
import { checkSubscriptionLimits } from '../middlewares/authorization.middleware.js';
import { UserRepository } from '../repositories/user.repository.js';

const userRepo = new UserRepository();

router.post('/users',
  authenticateToken,
  checkSubscriptionLimits('max_users', async (orgId) => {
    return await userRepo.countByOrganisation(orgId);
  }),
  createUser
);
```

## Error Handling

### Setup Global Error Handling
```javascript
// In app.js or main server file
import { setupErrorHandling } from '../middlewares/index.js';

// After all routes
setupErrorHandling(app);
```

### Async Route Handlers
```javascript
import { asyncHandler } from '../middlewares/errorHandler.middleware.js';

router.get('/async-endpoint', asyncHandler(async (req, res) => {
  const data = await someAsyncOperation();
  res.json(new ApiResponse(200, data, 'Success'));
}));
```

## Security Enhancements

### Input Sanitization
```javascript
import { sanitizeInput } from '../middlewares/validation.middleware.js';

// Global sanitization
app.use(sanitizeInput());

// Route-specific sanitization
router.post('/user-input', sanitizeInput('body'), controller);
```

### Device Fingerprinting
```javascript
// Automatically included in authenticateToken middleware
// Access via req.device_info in controllers
const handleLogin = (req, res) => {
  console.log(req.device_info); // { user_agent, ip_address, device_fingerprint }
};
```

## Testing the Migration

### 1. Update Route Files
Replace old middleware imports with new ones in all route files.

### 2. Test Authentication
```javascript
// Test with valid JWT token
curl -H "Authorization: Bearer <token>" http://localhost:3000/api/users
```

### 3. Test Permissions
```javascript
// Test with different roles and permissions
// Should get 403 for insufficient permissions
// Should get 200 for valid permissions
```

### 4. Test Organization Scoping
```javascript
// Users should only see data from their organization
// Admin users might see cross-org data based on permissions
```

### 5. Test Rate Limiting
```javascript
// Rapidly send requests to trigger rate limits
// Should get 429 responses when limits exceeded
```

## Cleanup Steps

### 1. Remove Deprecated Files
After confirming all routes work with new middleware:
```bash
rm middlewares/level.middleware.js
rm middlewares/role.middleware.js
rm middlewares/permission.middleware.js
rm middlewares/superadminAccess.middleware.js
rm middlewares/validate.middleware.js
rm middlewares/dynamicTierAccess.middleware.js
rm middlewares/fetchClientCredentials.js
```

### 2. Update Import Statements
Replace all old middleware imports across the codebase.

### 3. Test Thoroughly
Ensure all functionality works as expected with new middleware.

## Benefits of New System

1. **Better Security**: JWT with session management, device fingerprinting
2. **Flexible Permissions**: JSONB-based RBAC with wildcard support
3. **Multi-Tenancy**: Automatic organization scoping
4. **Subscription Control**: Feature and limit enforcement
5. **Better Error Handling**: Comprehensive error management
6. **Performance**: Efficient rate limiting and caching
7. **Maintainability**: Centralized, well-documented middleware

## Support

If you encounter issues during migration:
1. Check the console logs for detailed error messages
2. Verify JWT tokens are properly formatted
3. Ensure user roles and permissions are correctly set up
4. Test with super admin account first (bypasses most restrictions)
5. Review the middleware index.js for available options