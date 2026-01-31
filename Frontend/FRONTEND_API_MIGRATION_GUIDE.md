# Frontend API Migration Guide

This document outlines the frontend changes made to migrate from the legacy backend (port 4000) to the unified SIEM-dev backend (port 5001).

## Changes Made

### 1. Created Centralized API Service (`src/lib/api.ts`)

A unified API service with:
- **Authentication handling**: Automatically includes JWT tokens from localStorage
- **Error handling**: Consistent error handling across all API calls
- **Fallback support**: Graceful fallback to legacy APIs when needed
- **Organized endpoints**: Grouped by functionality (RBAC, Wazuh, JIRA, Tickets)

### 2. Updated Components

#### JIRA/Tickets Components
- ✅ `src/components/alerts/jira-tickets.tsx` - Updated all JIRA API calls
- ✅ `src/app/(client)/tickets/page.tsx` - Updated to use new API
- ✅ `src/components/alerts/live-alerts-table.tsx` - Updated ticket creation

#### Dashboard Components  
- ✅ `src/components/dashboard/dashboard.tsx` - Added Wazuh API with RBAC fallback
- ✅ `src/contexts/ThreatDataContext.tsx` - Updated alerts fetching with fallback

#### Agents Components
- ✅ `src/app/(client)/agents/page.tsx` - Updated agents fetching with fallback

#### Alerts Components
- ✅ `src/app/(client)/alerts/page.tsx` - Updated JIRA integration

## API Endpoint Mapping

### Old API (Legacy Backend - Port 4000)
```
http://localhost:4000/agents-summary
http://localhost:4000/alerts  
http://localhost:4000/dashboard-metrics
http://localhost:4000/compliance
http://localhost:4000/jira-issues
http://localhost:4000/create-jira-issue
http://localhost:4000/jira-issue/:key/transition
http://localhost:4000/jira-delete-issue/:key
```

### New API (Unified Backend - Port 5001)
```
http://localhost:5001/api/v1/wazuh/agents-summary
http://localhost:5001/api/v1/wazuh/alerts
http://localhost:5001/api/v1/wazuh/dashboard-metrics  
http://localhost:5001/api/v1/wazuh/compliance
http://localhost:5001/api/v1/jira/jira-issues
http://localhost:5001/api/v1/jira/create-jira-issue
http://localhost:5001/api/v1/jira/jira-issue/:key/transition
http://localhost:5001/api/v1/jira/jira-delete-issue/:key
http://localhost:5001/api/v1/tickets/*
```

## Testing the Migration

### Prerequisites
1. **Unified Backend Running**: 
   ```bash
   cd "C:\Codec Networks\SOC\SOC Dashboard Test3\SIEM-dev"
   npm run dev
   ```
   Should be running on http://localhost:5001

2. **Frontend Running**:
   ```bash
   cd "C:\Codec Networks\SOC\SOC Dashboard Test3\SOC_Dashboard-Satyam" 
   npm run dev
   ```
   Should be running on http://localhost:3000

3. **Authentication Token**: Make sure you're logged in to get a valid JWT token

### Test Cases

#### 1. Dashboard Metrics ✅
- **URL**: http://localhost:3000/dashboard
- **Expected**: Dashboard loads with metrics, stats, and graphs
- **Fallback**: If Wazuh API fails, falls back to RBAC API
- **Check Console**: Look for "[!] Wazuh API unavailable, falling back to RBAC API" if fallback occurs

#### 2. Alerts Management ✅
- **URL**: http://localhost:3000/alerts
- **Expected**: 
  - Live alerts table loads
  - Can create tickets from alerts
  - JIRA integration works
- **Check**: Network tab shows calls to `/api/v1/wazuh/alerts` and `/api/v1/jira/*`

#### 3. Agents Management ✅  
- **URL**: http://localhost:3000/agents
- **Expected**:
  - Agents list loads with SCA scores
  - CIS compliance checks visible
  - Vulnerabilities data shown
- **Check**: Network tab shows calls to `/api/v1/wazuh/agents-summary`

#### 4. Tickets/JIRA ✅
- **URL**: http://localhost:3000/tickets
- **Expected**:
  - JIRA tickets list loads
  - Can transition ticket status
  - Can delete tickets
- **Actions to Test**:
  - Click "Start Investigating" button
  - Click "Close Ticket" button  
  - Click "Delete Ticket" button
- **Check**: Network tab shows calls to `/api/v1/jira/*`

#### 5. Ticket Creation ✅
- **URL**: http://localhost:3000/alerts
- **Steps**:
  1. Find an alert in the table
  2. Click "Create Ticket" button
  3. Verify ticket creation succeeds
- **Expected**: Success message and API call to `/api/v1/jira/create-jira-issue`

### Authentication Testing

All API calls now include JWT authentication. Test that:

1. **Logged in**: All API calls work normally
2. **Logged out**: API calls return 401 errors
3. **Expired token**: API calls return 401 errors and user is redirected to login

### Error Handling Testing

Test error scenarios:

1. **Backend Down**: 
   - Stop the SIEM-dev backend
   - Check that fallback APIs are used where available
   - Check error messages are user-friendly

2. **Invalid Credentials**:
   - Configure invalid Wazuh/Indexer credentials  
   - Check that appropriate error messages are shown

3. **Network Issues**:
   - Simulate network disconnection
   - Check that loading states and error messages work properly

## Environment Configuration

### Development (.env.local)
```
NEXT_PUBLIC_RBAC_BASE_IP=http://localhost:5001/api/v1
```

### Production
Update the environment variable to point to your production unified backend.

## Rollback Plan

If issues occur, you can rollback by:

1. **Start Legacy Backend**:
   ```bash
   cd "C:\Codec Networks\SOC\SOC Dashboard Test3\SOC_Dashboard-Satyam\backend"
   node server.js
   ```

2. **Use Legacy API**: Modify `src/lib/api.ts` to use `legacyApi` instead of the new APIs

## Monitoring & Troubleshooting

### Console Messages
- **Success**: No error messages, smooth API calls
- **Fallback**: "[!] Wazuh API unavailable, falling back to RBAC API"
- **Errors**: Check browser console for detailed error messages

### Network Tab
- Check that API calls go to port 5001 instead of 4000
- Verify authentication headers are included
- Monitor response times and error codes

### Common Issues
1. **CORS Errors**: Ensure SIEM-dev backend has proper CORS configuration
2. **Auth Errors**: Verify JWT token is valid and properly included
3. **Missing Data**: Check that client credentials are configured in SIEM-dev
4. **Performance**: Monitor if unified backend is slower than separate backends

## Benefits of Migration

✅ **Single Backend**: Only need to run one backend service  
✅ **Consistent Auth**: JWT authentication on all endpoints  
✅ **Better Error Handling**: Unified error response format  
✅ **Multi-tenant**: Proper client isolation  
✅ **Enhanced Features**: New ticket management capabilities  
✅ **Fallback Support**: Graceful degradation if APIs are unavailable  

## Next Steps

1. **Remove Legacy Backend**: Once testing confirms everything works
2. **Update Production**: Deploy unified backend to production
3. **Environment Variables**: Update production frontend environment variables
4. **Monitoring**: Set up monitoring for the unified backend
5. **Documentation**: Update API documentation for the team