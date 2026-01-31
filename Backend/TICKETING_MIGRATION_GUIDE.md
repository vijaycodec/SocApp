# Complete Backend Migration Guide

This guide documents the complete migration of all backend functionality from SOC_Dashboard-Satyam to SIEM-dev, creating a unified backend system.

## Backend Migration (Completed)

### 1. Controllers Added
- `controllers/jira.controller.js` - JIRA integration endpoints
- `controllers/ticket.controller.js` - Local ticket management
- `controllers/agents.controller.js` - Wazuh agents management
- `controllers/alerts.controller.js` - Security alerts management
- `controllers/dashboardMetrics.controller.js` - Dashboard metrics and statistics
- `controllers/compliance.controller.js` - Compliance rules and data

### 2. Services Added
- `services/wazuhExtended.service.js` - Extended Wazuh integration services
- `services/cacheRefresh.service.js` - Automatic cache refresh service

### 3. Models Added
- `models/ticket.model.js` - Ticket data model with JIRA integration support

### 4. Routes Added
- `routes/jira.routes.js` - JIRA API routes
- `routes/ticket.routes.js` - Local ticket management routes
- `routes/wazuh.routes.js` - Wazuh integration routes (agents, alerts, metrics, compliance)

### 5. API Endpoints Available

#### JIRA Integration Endpoints (Prefix: `/api/v1/jira`)
- `POST /create-jira-issue` - Create JIRA issue
- `GET /jira-issues` - Get all JIRA issues
- `POST /jira-issue/:key/transition` - Transition JIRA issue status
- `DELETE /jira-delete-issue/:key` - Delete JIRA issue

#### Local Ticket Management Endpoints (Prefix: `/api/v1/tickets`)
- `POST /` - Create ticket
- `GET /` - Get tickets (with filtering and pagination)
- `GET /stats` - Get ticket statistics
- `GET /:ticketId` - Get ticket by ID
- `PUT /:ticketId` - Update ticket
- `DELETE /:ticketId` - Delete ticket
- `POST /:ticketId/comments` - Add comment to ticket

#### Wazuh Integration Endpoints (Prefix: `/api/v1/wazuh`)
- `GET /agents-summary` - Get agents summary with SCA scores and vulnerabilities
- `GET /alerts` - Get security alerts with IP geolocation
- `GET /dashboard-metrics` - Get dashboard metrics and statistics
- `GET /compliance` - Get compliance rules and data

### 6. Environment Variables Added
Add these to your `.env` file:
```
PORT=5001
MONGO_URI=mongodb://localhost:27017/siem
JWT_SECRET=mySuperSecretJWTKey123

# Redis Configuration
REDIS_URL=redis://localhost:6379

# JIRA Configuration
JIRA_BASE_URL=https://your-domain.atlassian.net
JIRA_EMAIL=your-email@domain.com
JIRA_API_TOKEN=your-jira-api-token
JIRA_PROJECT_KEY=SEC
```

**Note:** Wazuh and Indexer credentials are now stored per-client in the database through the client management interface, providing proper multi-tenant isolation.

## Frontend Components to Migrate

The following frontend components from SOC_Dashboard-Satyam need to be integrated into your frontend application:

### 1. Pages
- `src/app/(client)/tickets/page.tsx` - Main tickets page

### 2. Components
- `src/components/tickets/CreateTicketModal.tsx` - Ticket creation modal
- `src/components/tickets/recent-tickets.tsx` - Recent tickets component  
- `src/components/alerts/jira-tickets.tsx` - JIRA tickets table component

### 3. API Integration Notes

Update the API calls in the frontend components to match the new backend structure:

**Old API calls (SOC_Dashboard-Satyam backend - Port 4000):**
```javascript
// Wazuh/Security endpoints
fetch('http://localhost:4000/agents-summary')
fetch('http://localhost:4000/alerts')
fetch('http://localhost:4000/dashboard-metrics')
fetch('http://localhost:4000/compliance')

// JIRA endpoints
fetch('http://localhost:4000/jira-issues')
fetch('http://localhost:4000/jira-issue/${key}/transition')
fetch('http://localhost:4000/jira-delete-issue/${key}')
```

**New API calls (SIEM-dev unified backend - Port 5001):**
```javascript
// Wazuh/Security endpoints
fetch('http://localhost:5001/api/v1/wazuh/agents-summary')
fetch('http://localhost:5001/api/v1/wazuh/alerts')
fetch('http://localhost:5001/api/v1/wazuh/dashboard-metrics')
fetch('http://localhost:5001/api/v1/wazuh/compliance')

// JIRA endpoints
fetch('http://localhost:5001/api/v1/jira/jira-issues')
fetch('http://localhost:5001/api/v1/jira/jira-issue/${key}/transition')
fetch('http://localhost:5001/api/v1/jira/jira-delete-issue/${key}')

// New ticket management endpoints
fetch('http://localhost:5001/api/v1/tickets')
fetch('http://localhost:5001/api/v1/tickets/stats')
```

### 4. Component Dependencies

Make sure your frontend project has these dependencies:
- `@heroicons/react` - For icons
- `clsx` - For conditional CSS classes

### 5. Authentication Integration

The new backend requires JWT authentication. Ensure your frontend includes the JWT token in API requests:

```javascript
const token = localStorage.getItem('token'); // or however you store the token

fetch('/api/v1/tickets', {
  headers: {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
  }
})
```

## Usage Examples

### Creating a Ticket from Alert
```javascript
const createTicketFromAlert = async (alertData) => {
  const response = await fetch('/api/v1/tickets', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      title: `Security Alert: ${alertData.rule}`,
      description: alertData.description,
      severity: alertData.severity,
      alertId: alertData.id,
      ruleId: alertData.ruleId,
      ruleName: alertData.rule,
      hostName: alertData.host,
      agentName: alertData.agent,
      sourceIp: alertData.srcip,
      alertTimestamp: alertData.timestamp
    })
  });
  
  return response.json();
};
```

### Creating JIRA Issue from Ticket
```javascript
const createJiraFromTicket = async (ticketData) => {
  const response = await fetch('/api/v1/jira/create-jira-issue', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      summary: ticketData.title,
      descriptionText: ticketData.description,
      dateTime: ticketData.alertTimestamp,
      host: ticketData.hostName,
      agent: ticketData.agentName,
      rule: ticketData.ruleName,
      ruleId: ticketData.ruleId,
      severity: ticketData.severity
    })
  });
  
  return response.json();
};
```

## Running the Unified Backend

### Prerequisites
1. **Node.js** installed
2. **MongoDB** running (for data storage)
3. **Redis** running (for caching)

### Setup Steps

1. **Install Dependencies**:
```bash
cd "C:\Codec Networks\SOC\SOC Dashboard Test3\SIEM-dev"
npm install
```

2. **Configure Environment**:
```bash
# Copy example environment file
copy example.env .env

# Edit .env with your actual values:
# - MongoDB connection string
# - Redis URL
# - JWT secret
# - JIRA credentials (if using)
```

3. **Setup Client Credentials**:
   - Use the client management interface to configure Wazuh and Indexer credentials for each client
   - This provides proper multi-tenant isolation

4. **Start the Unified Backend**:
```bash
npm run dev
```

The unified backend will run on **http://localhost:5001**

### Frontend Integration

Update your frontend to point to the new unified backend:

```javascript
// Base API URL
const API_BASE_URL = 'http://localhost:5001/api/v1';

// Include authentication in all requests
const makeAuthenticatedRequest = async (endpoint, options = {}) => {
  const token = localStorage.getItem('token');
  
  return fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
      ...options.headers
    }
  });
};
```

## Migration Benefits

- **Unified Architecture**: Single backend handling all functionality
- **Consistent API Structure**: All endpoints follow `/api/v1` pattern
- **Enhanced Security**: JWT authentication on all endpoints
- **Multi-tenant Support**: Proper client isolation for Wazuh/Indexer credentials
- **Improved Performance**: Redis caching for frequently accessed data
- **Better Error Handling**: Standardized ApiResponse and ApiError patterns
- **Scalable Design**: Modular controller/service architecture
- **Rich Ticketing**: Local ticket management with JIRA integration
- **Real-time Monitoring**: Wazuh agents, alerts, and compliance monitoring

## Legacy Backend Removal

After confirming everything works correctly, you can:

1. **Stop the legacy backend** (port 4000)
2. **Remove the SOC_Dashboard-Satyam/backend directory**
3. **Update any remaining frontend references** to use the unified backend
4. **Remove old environment variables** that pointed to the legacy backend

Your entire system now runs on a single, unified backend with proper authentication, multi-tenancy, and comprehensive functionality!