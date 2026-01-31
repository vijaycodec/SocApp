# SOC Dashboard - User Manual

**Version 1.0**
**Last Updated: October 2025**

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Getting Started](#2-getting-started)
3. [Dashboard Overview](#3-dashboard-overview)
4. [Authentication & Login](#4-authentication--login)
5. [Main Dashboard](#5-main-dashboard)
6. [Live Alerts Management](#6-live-alerts-management)
7. [Ticket Management](#7-ticket-management)
8. [Global Threat Intelligence](#8-global-threat-intelligence)
9. [SIEM Overview](#9-siem-overview)
10. [Viewing Agents Status](#10-viewing-agents-status)
11. [Asset Register](#11-asset-register)
12. [Risk Matrix](#12-risk-matrix)
13. [Compliance Management](#13-compliance-management)
14. [Reports & Analytics](#14-reports--analytics)
15. [Client Mode Operations](#15-client-mode-operations)
16. [Attack Visualization](#16-attack-visualization)
17. [Alert Severity Classification](#17-alert-severity-classification)
18. [Incident Response Workflow](#18-incident-response-workflow)
19. [Search & Filtering](#19-search--filtering)
20. [User Profile Settings](#20-user-profile-settings)
21. [Notification Settings](#21-notification-settings)
22. [Dark Mode & Themes](#22-dark-mode--themes)
23. [Password Management](#23-password-management)
24. [Troubleshooting Guide](#24-troubleshooting-guide)
25. [Best Practices for SOC Analysts](#25-best-practices-for-soc-analysts)
26. [Glossary](#26-glossary)
27. [FAQ](#27-faq)
28. [Contact & Support](#28-contact--support)

---

## 1. Introduction

### 1.1 About SOC Dashboard

The SOC (Security Operations Center) Dashboard is a comprehensive security monitoring platform designed for security analysts and SOC teams. It provides real-time visibility into security events, alerts, threats, and compliance status across your organization.

### 1.2 Key Features

- **Real-time Alert Monitoring**: Live security alerts from Wazuh SIEM
- **Ticket Management**: Convert alerts to tickets with full lifecycle tracking
- **Global Threat Intelligence**: Interactive threat maps showing worldwide attacks
- **Compliance Tracking**: NIST, CIS framework monitoring
- **Asset Management**: Track and monitor security assets
- **Risk Assessment**: Visual risk matrix for threat prioritization
- **Advanced Analytics**: Comprehensive reports and visualizations

### 1.3 Who Should Use This Manual

This manual is designed for:
- **SOC Analysts**: Day-to-day monitoring and alert triage
- **Security Analysts**: Investigation and incident response
- **SOC Team Members**: Daily operational tasks

### 1.4 Document Conventions

Throughout this manual:
- **Bold text** highlights important UI elements or actions
- 📸 Screenshot placeholders show where visual examples should be inserted
- 💡 Tips provide helpful suggestions
- ⚠️ Warnings indicate critical information

---

## 2. Getting Started

### 2.1 Accessing the Dashboard

1. Open your web browser (Chrome, Firefox, Safari, or Edge)
2. Navigate to the SOC Dashboard URL provided by your administrator
3. You will see the login page

**Recommended browsers:**
- Google Chrome 90+
- Mozilla Firefox 88+
- Safari 14+
- Microsoft Edge 90+

### 2.2 Screen Requirements

For best experience:
- Screen resolution: 1920x1080 or higher
- Minimum: 1366x768

📸 **Screenshot: Login page**
*Path: /screenshots/login-page.png*

---

## 3. Dashboard Overview

### 3.1 Dashboard Layout

The dashboard consists of:

1. **Header Bar** (Top):
   - Logo
   - Client selector (if in multi-client mode)
   - Notifications bell
   - User menu

2. **Sidebar** (Left):
   - Navigation menu

3. **Main Content Area** (Center):
   - Dynamic content based on selected page

📸 **Screenshot: Full dashboard layout with components labeled**
*Path: /screenshots/dashboard-layout.png*

### 3.2 Navigation Menu

| Icon | Menu Item | Description |
|------|-----------|-------------|
| 🏠 | Dashboard | Main security overview |
| 🚨 | Alerts | Live security alerts |
| 🎫 | Tickets | Incident tickets |
| 🌍 | Threats | Global threat intelligence |
| 📊 | SIEM | Log analysis |
| 🖥️ | Agents | Agent status |
| 📋 | Asset Register | Asset inventory |
| ⚠️ | Risk Matrix | Risk assessment |
| ✅ | Compliance | Compliance monitoring |
| 📈 | Reports | Analytics and reports |
| ⚙️ | Settings | User preferences |

### 3.3 Header Components

**Client Selector** (if enabled):
- Switch between organizations/clients
- Filters all data based on selection

**Notifications Bell**:
- Shows unread notification count
- Click to view alerts

**User Menu**:
- Your name/username
- Profile settings
- Logout

📸 **Screenshot: Header with client selector and notifications**
*Path: /screenshots/header-components.png*

---

## 4. Authentication & Login

### 4.1 Logging In

**Steps:**
1. Enter your **username** or **email**
2. Enter your **password**
3. Click **"Sign In"**
4. If 2FA is enabled, enter the authentication code

📸 **Screenshot: Login form**
*Path: /screenshots/login-form.png*

### 4.2 Password Requirements

Your password must contain:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

⚠️ **Note**: Passwords are case-sensitive.

### 4.3 Forgot Password

If you forget your password:

1. Click **"Forgot Password?"** on login page
2. Enter your email address
3. Check email for reset link (valid for 1 hour)
4. Click link and create new password
5. Login with new credentials

📸 **Screenshot: Forgot password page**
*Path: /screenshots/forgot-password.png*

### 4.4 First Login

On first login, you'll be prompted to change your password:
1. Enter current (temporary) password
2. Enter new password
3. Confirm new password
4. Click **"Update Password"**

💡 **Best Practice**: Change default password immediately.

### 4.5 Session Timeout

- Sessions expire after 8 hours of inactivity
- You'll be redirected to login page
- Simply log in again to continue

---

## 5. Main Dashboard

### 5.1 Dashboard Overview

The main dashboard shows:
- Real-time security metrics
- Alert statistics
- Global threat map
- Alert trends
- System health

📸 **Screenshot: Main dashboard full view**
*Path: /screenshots/main-dashboard.png*

### 5.2 Security Metrics Panel

Top cards display key metrics:

| Metric | Description |
|--------|-------------|
| **Total Alerts (24hr)** | All alerts in last 24 hours |
| **Critical Alerts** | High-priority alerts (red) |
| **Major Alerts** | Medium-priority alerts (orange) |
| **Minor Alerts** | Low-priority alerts (yellow) |
| **Active Agents** | Connected monitoring agents |

📸 **Screenshot: Metrics panel with statistics cards**
*Path: /screenshots/metrics-panel.png*

**Auto-Refresh:**
- Metrics update every 5 seconds
- "Last updated" timestamp shown

### 5.3 Global Threat Map

Interactive 3D globe showing:
- Attack origins (source countries)
- Attack destinations (targets)
- Animated attack paths
- Real-time threat data

**Interactions:**
- **Auto-rotate**: Globe spins automatically
- **Drag**: Click and drag to rotate
- **Zoom**: Scroll to zoom in/out
- **Fullscreen**: Click expand icon

📸 **Screenshot: Global threat map with attack arcs**
*Path: /screenshots/threat-map.png*

💡 **Tip**: Click fullscreen for better visualization during briefings.

### 5.4 Alert Severity Chart

Donut chart showing alert breakdown:
- **Critical** (Red): Severity 15+
- **Major** (Orange): Severity 11-14
- **Minor** (Yellow): Severity 7-10

Center shows total alert count.

📸 **Screenshot: Severity donut chart**
*Path: /screenshots/severity-chart.png*

### 5.5 Alerts Timeline

Line graph showing alert trends over time:
- X-axis: Time periods
- Y-axis: Alert count
- Multiple lines for each severity level
- Hover for exact values

📸 **Screenshot: Alerts timeline graph**
*Path: /screenshots/alerts-timeline.png*

### 5.6 Global Threat Intelligence Feed

Displays recent threat indicators:
- Malware signatures
- Compromised IPs
- Threat actor activity
- CVE information

📸 **Screenshot: Threat intelligence feed**
*Path: /screenshots/threat-feed.png*

---

## 6. Live Alerts Management

### 6.1 Accessing Alerts

Click **Alerts** (🚨) in the sidebar.

The Alerts page shows:
- All security alerts
- Severity-based filtering
- Alert details
- Ticket creation

📸 **Screenshot: Alerts page overview**
*Path: /screenshots/alerts-page.png*

### 6.2 Alert Distribution Charts

Two charts at the top:

**1. Severity Distribution:**
- Critical, Major, Minor percentages
- Visual breakdown

**2. Ticket Status:**
- New Alerts (no ticket yet)
- Ticket Created (already handled)

📸 **Screenshot: Alert distribution charts**
*Path: /screenshots/alert-charts.png*

### 6.3 Alerts Table

| Column | Description |
|--------|-------------|
| **Alert ID** | Unique identifier |
| **Severity** | Critical/Major/Minor badge |
| **Description** | Alert message |
| **Timestamp** | When it occurred |
| **Host** | Target system |
| **Agent** | Monitoring agent |
| **Rule** | Triggered rule name |
| **Actions** | View details, Create ticket |

📸 **Screenshot: Alerts table**
*Path: /screenshots/alerts-table.png*

### 6.4 Severity Badges

Quick visual indicators:
- 🔴 **CRITICAL** - Immediate action required
- 🟠 **MAJOR** - High priority
- 🟡 **MINOR** - Medium priority

### 6.5 Filtering Alerts

**Filter by Severity:**
- All / Critical / Major / Minor

**Filter by Ticket Status:**
- All / With Tickets / Without Tickets

**Search:**
- Search by description, hostname, or agent

📸 **Screenshot: Alert filters**
*Path: /screenshots/alert-filters.png*

### 6.6 Viewing Alert Details

Click any alert row to see full details:
- Complete description
- Timestamp
- Source IP
- Destination IP
- Rule details
- Full JSON data
- Related events

📸 **Screenshot: Alert detail modal**
*Path: /screenshots/alert-detail.png*

### 6.7 Creating Tickets from Alerts

**Steps:**
1. Click **"Create Ticket"** button in alert row
2. Modal opens with pre-filled info:
   - Title (from alert)
   - Description
   - Alert ID
   - Host, Agent, Rule data
3. Fill additional fields:
   - **Priority**: Low/Medium/High/Critical
   - **Category**: Incident type
   - **Assigned To**: Team member (optional)
   - **Tags**: Keywords
4. Click **"Create Ticket"**
5. Success message shows ticket number

📸 **Screenshot: Create ticket from alert modal**
*Path: /screenshots/create-ticket-modal.png*

⚠️ **Note**: Cannot create duplicate tickets for same alert.

### 6.8 Refresh Alerts

- Click **"Refresh"** button (top-right)
- Manually reload alerts
- Updates ticket mappings

### 6.9 Collapse Charts

Save screen space:
- Click **"Collapse Charts"**
- Charts hide, table expands
- Click **"Expand Charts"** to restore

---

## 7. Ticket Management

### 7.1 Accessing Tickets

Click **Tickets** (🎫) in the sidebar.

Ticket Management features:
- View all incident tickets
- Track status workflow
- Assign tickets
- Add resolution notes
- Monitor progress

📸 **Screenshot: Tickets page**
*Path: /screenshots/tickets-page.png*

### 7.2 Ticket Status Overview

Dashboard shows:
- **Total Tickets**
- **Open** (Red) - New, need attention
- **Investigating** (Blue) - In progress
- **Resolved** (Green) - Completed

Includes donut chart and progress bars.

📸 **Screenshot: Ticket status dashboard**
*Path: /screenshots/ticket-status.png*

### 7.3 Tickets Table

| Column | Description |
|--------|-------------|
| **Ticket #** | Unique number (TKT-001234) |
| **Title** | Brief summary |
| **Priority** | Low/Medium/High/Critical |
| **Severity** | Low/Medium/High/Critical |
| **Status** | Open/Investigating/Resolved |
| **Created By** | Creator username |
| **Assigned To** | Current owner |
| **Created** | Creation date/time |
| **Actions** | View, Edit, Update |

📸 **Screenshot: Tickets table**
*Path: /screenshots/tickets-table.png*

### 7.4 Priority Levels

| Priority | Response SLA | Use Case |
|----------|--------------|----------|
| **Critical** | < 1 hour | Active breaches |
| **High** | < 4 hours | Malware, suspicious activity |
| **Medium** | < 24 hours | Policy violations |
| **Low** | < 72 hours | Informational |

### 7.5 Viewing Ticket Details

Click any ticket to see:
- Full description
- Alert information (if linked)
- Assignment details
- Timestamps
- Tags and notes
- Resolution details

📸 **Screenshot: Ticket detail modal**
*Path: /screenshots/ticket-detail.png*

### 7.6 Updating Ticket Status

**Workflow:**
```
Open → Investigating → Resolved
```

**Steps:**
1. Click **"Update Status"** button
2. Select new status
3. For **Resolved**:
   - Select resolution type:
     - **True Positive**: Real incident
     - **False Positive**: False alarm
   - Enter **Resolution Notes** (required)
   - Include: actions taken, root cause, remediation
4. Click **"Update"**

📸 **Screenshot: Update status modal**
*Path: /screenshots/update-status.png*

⚠️ **Important**: Resolved tickets cannot be reopened.

### 7.7 Assigning Tickets

Assign work to team members:
1. Click **"Assign"** button
2. Select user from dropdown
3. Click **"Assign"**
4. Assignee receives notification

💡 **Tip**: Assign critical tickets immediately.

### 7.8 Creating Manual Tickets

Create tickets not from alerts:
1. Click **"Create Ticket"** (top-right)
2. Fill required fields:
   - Title
   - Description
   - Category
   - Priority
   - Severity
3. Optional: Assigned To, Tags, Asset
4. Click **"Create Ticket"**

📸 **Screenshot: Create manual ticket form**
*Path: /screenshots/create-manual-ticket.png*

### 7.9 Filtering Tickets

**Filter Options:**
- By Status: All/Open/Investigating/Resolved
- By Priority: All/Critical/High/Medium/Low
- By Assignment: All/My Tickets/Unassigned
- Search: By ticket #, title, description

📸 **Screenshot: Ticket filters**
*Path: /screenshots/ticket-filters.png*

### 7.10 Refresh Tickets

- Click **"Refresh"** button (top-right)
- Reloads all tickets
- Updates distributions

---

## 8. Global Threat Intelligence

### 8.1 Accessing Threats Page

Click **Threats** (🌍) in the sidebar.

Features:
- Real-time threat monitoring
- Attack pattern visualization
- Threat actor tracking
- Indicators of Compromise (IOCs)
- Geopolitical assessment

📸 **Screenshot: Threats page**
*Path: /screenshots/threats-page.png*

### 8.2 Live Monitoring Status

- Green pulsing indicator = Active monitoring
- Real-time threat data feeds

### 8.3 Global Attack Map

Large interactive map showing:
- 3D globe with attack paths
- Source and target countries
- Animated attack arcs
- High-activity regions

**Interactions:**
- Rotate: Auto or manual drag
- Zoom: Scroll wheel
- Click: Country details
- Fullscreen: Expand view

📸 **Screenshot: Attack map**
*Path: /screenshots/attack-map.png*

### 8.4 Active Threat Intelligence

Left panel shows current threats:

**Each threat card includes:**
- Threat title
- Severity badge
- Description
- **IOCs** (Indicators of Compromise):
  - Malicious IPs
  - File hashes
  - Domains
  - Filenames
- Affected countries
- Timestamp

📸 **Screenshot: Threat intelligence cards**
*Path: /screenshots/threat-cards.png*

**Example threats:**
- APT campaigns
- Ransomware variants
- Phishing campaigns

### 8.5 Geopolitical Threat Assessment

Right panel shows regional risks:

| Region | Threat Level | Activities |
|--------|--------------|------------|
| Eastern Europe | High | State-sponsored attacks |
| Southeast Asia | Medium | Financial fraud |
| Middle East | Medium | Espionage |
| North America | Low | Routine scanning |

📸 **Screenshot: Geopolitical assessment**
*Path: /screenshots/geopolitical.png*

### 8.6 Threat Statistics

Bottom cards show:
- **Active Threats**: 1,247 current threats
- **Countries Affected**: 47 geographic spread
- **IOCs Detected**: 8,921 indicators
- **Blocked Attacks**: 15,634 prevented

📸 **Screenshot: Threat statistics**
*Path: /screenshots/threat-stats.png*

### 8.7 Using Threat Intelligence

**For Daily Monitoring:**
1. Review threat feed at shift start
2. Cross-reference IOCs with your alerts
3. Note emerging threat actors
4. Brief team on critical threats

💡 **Best Practice**: Check threat intelligence twice per shift.

---

## 9. SIEM Overview

### 9.1 Accessing SIEM Page

Click **SIEM** (📊) in the sidebar.

View:
- Wazuh SIEM connection status
- Log summaries
- Recent events
- Agent statistics

📸 **Screenshot: SIEM page**
*Path: /screenshots/siem-page.png*

### 9.2 Connection Status

Status indicators:
- ✅ **Connected**: Green, operational
- ⚠️ **Degraded**: Yellow, partial issues
- ❌ **Disconnected**: Red, no connection

Shows:
- Wazuh Manager IP
- Last connection time
- Health percentage

📸 **Screenshot: SIEM connection status**
*Path: /screenshots/siem-status.png*

### 9.3 Viewing Log Summaries

- Recent log entries
- Event counts
- Rule triggers
- Alert summaries

💡 **Note**: Full log search may require additional permissions.

---

## 10. Viewing Agents Status

### 10.1 Accessing Agents Page

Click **Agents** (🖥️) in the sidebar.

View:
- All connected agents
- Agent health status
- Version information
- Last communication time

📸 **Screenshot: Agents page**
*Path: /screenshots/agents-page.png*

### 10.2 Agent Summary

Cards show:
- **Total Agents**: All registered
- **Active**: Connected and reporting
- **Disconnected**: Offline agents
- **Never Connected**: Pending setup

### 10.3 Agents Table

| Column | Information |
|--------|-------------|
| **Agent ID** | Unique ID |
| **Agent Name** | Hostname |
| **IP Address** | Network IP |
| **Status** | Active/Disconnected badge |
| **OS** | Operating system |
| **Version** | Agent software version |
| **Last Keep Alive** | Last contact time |

📸 **Screenshot: Agents table**
*Path: /screenshots/agents-table.png*

### 10.4 Agent Status

**Badges:**
- 🟢 **Active**: Healthy and reporting
- 🔴 **Disconnected**: Offline or unreachable
- ⚪ **Never Connected**: Not yet initialized

### 10.5 Viewing Agent Details

Click agent row to see:
- Hostname
- IP and MAC address
- OS details
- Registration date
- Alert statistics
- Recent activity

📸 **Screenshot: Agent details**
*Path: /screenshots/agent-details.png*

💡 **Tip**: Report disconnected agents to your administrator.

---

## 11. Asset Register

### 11.1 Accessing Asset Register

Click **Asset Register** (📋) in the sidebar.

Manage:
- IT asset inventory
- Security asset tracking
- Asset details and metadata
- Asset relationships

📸 **Screenshot: Asset Register page**
*Path: /screenshots/asset-register.png*

### 11.2 Assets Overview

View all organizational assets:
- Servers
- Workstations
- Network devices
- Applications
- Cloud resources

### 11.3 Assets Table

| Column | Description |
|--------|-------------|
| **Asset Name** | Device/system name |
| **Asset Tag** | Unique identifier |
| **Type** | Server/Workstation/Network/App |
| **IP Address** | Network address |
| **Owner** | Responsible person/team |
| **Status** | Active/Inactive/Maintenance |
| **Criticality** | Low/Medium/High/Critical |

📸 **Screenshot: Assets table**
*Path: /screenshots/assets-table.png*

### 11.4 Viewing Asset Details

Click asset to see:
- Full specifications
- Location information
- Associated vulnerabilities
- Related alerts
- Maintenance history
- Compliance status

📸 **Screenshot: Asset details modal**
*Path: /screenshots/asset-details.png*

### 11.5 Searching Assets

- Search by name, tag, IP
- Filter by type
- Filter by criticality
- Filter by status

💡 **Tip**: Link assets to tickets for better incident tracking.

---

## 12. Risk Matrix

### 12.1 Accessing Risk Matrix

Click **Risk Matrix** (⚠️) in the sidebar.

Visualize:
- Risk assessment grid
- Likelihood vs Impact
- Risk scores
- Mitigation priorities

📸 **Screenshot: Risk Matrix page**
*Path: /screenshots/risk-matrix.png*

### 12.2 Understanding the Matrix

**Grid Layout:**
- **Y-Axis**: Impact (Low → High)
- **X-Axis**: Likelihood (Low → High)
- **Color Coding**:
  - Green: Low risk
  - Yellow: Medium risk
  - Orange: High risk
  - Red: Critical risk

📸 **Screenshot: Risk matrix grid with risks plotted**
*Path: /screenshots/risk-grid.png*

### 12.3 Risk Levels

| Level | Color | Action Required |
|-------|-------|-----------------|
| **Critical** | Red | Immediate action |
| **High** | Orange | Priority mitigation |
| **Medium** | Yellow | Planned mitigation |
| **Low** | Green | Monitor and review |

### 12.4 Viewing Risks

Each risk shows:
- Risk ID
- Description
- Likelihood rating
- Impact rating
- Overall risk score
- Status (Open/Mitigating/Closed)
- Owner

### 12.5 Risk Details

Click risk for:
- Detailed description
- Affected assets
- Mitigation plan
- Progress updates
- Related incidents

📸 **Screenshot: Risk detail view**
*Path: /screenshots/risk-detail.png*

💡 **Best Practice**: Review risk matrix weekly with your team.

---

## 13. Compliance Management

### 13.1 Accessing Compliance

Click **Compliance** (✅) in the sidebar.

Track compliance with:
- NIST Framework
- CIS Controls
- Custom frameworks
- Regulatory requirements

📸 **Screenshot: Compliance page**
*Path: /screenshots/compliance-page.png*

### 13.2 Compliance Frameworks

Available frameworks:
- **NIST Cybersecurity Framework**
- **CIS Controls v8**
- **ISO 27001** (if configured)
- **PCI DSS** (if configured)
- Custom frameworks

### 13.3 Compliance Dashboard

Overview cards show:
- Overall compliance percentage
- Compliant controls (green)
- Non-compliant controls (red)
- In-progress controls (yellow)

📸 **Screenshot: Compliance dashboard with percentages**
*Path: /screenshots/compliance-dashboard.png*

### 13.4 Viewing Framework Details

Click framework to see:
- All control categories
- Individual controls
- Compliance status
- Evidence requirements
- Implementation status

📸 **Screenshot: NIST framework detail view**
*Path: /screenshots/nist-details.png*

### 13.5 Control Status

**Status indicators:**
- ✅ **Compliant**: Control implemented
- ⚠️ **Partial**: Partially implemented
- ❌ **Non-Compliant**: Not implemented
- 🔄 **In Progress**: Being implemented

### 13.6 Control Details

View details for each control:
- Control ID and description
- Implementation guidance
- Current status
- Evidence/documentation
- Last assessment date
- Responsible party

📸 **Screenshot: Control detail modal**
*Path: /screenshots/control-detail.png*

### 13.7 Compliance Reports

Generate reports showing:
- Compliance percentage
- Gap analysis
- Remediation priorities
- Trend over time

💡 **Tip**: Export compliance reports for auditors.

---

## 14. Reports & Analytics

### 14.1 Accessing Reports

Click **Reports** (📈) in the sidebar.

Generate and view:
- Security reports
- Alert analytics
- Ticket summaries
- Compliance reports
- Custom reports

📸 **Screenshot: Reports page**
*Path: /screenshots/reports-page.png*

### 14.2 Report Categories

**Available reports:**
- **Daily Security Summary**: 24-hour overview
- **Weekly Alert Report**: 7-day trends
- **Ticket Status Report**: Open/closed tickets
- **Compliance Status**: Framework compliance
- **Agent Health Report**: Agent status
- **Threat Intelligence Summary**: Latest threats

### 14.3 Generating Reports

**Steps:**
1. Select report type
2. Choose date range
3. Select filters (optional):
   - Severity
   - Status
   - Client (if applicable)
4. Click **"Generate Report"**
5. View online or download

📸 **Screenshot: Report generation form**
*Path: /screenshots/generate-report.png*

### 14.4 Report Formats

Export options:
- **PDF**: Formatted document
- **CSV**: Spreadsheet data
- **Excel**: Advanced spreadsheet
- **JSON**: Raw data

### 14.5 Scheduled Reports

View scheduled reports:
- Daily automated reports
- Weekly summaries
- Monthly compliance reports

Reports delivered via email or dashboard.

### 14.6 Report Filters

Filter report data by:
- Date range
- Severity level
- Status
- Priority
- Assignment
- Client/Organization

📸 **Screenshot: Report with filters applied**
*Path: /screenshots/report-filtered.png*

---

## 15. Client Mode Operations

### 15.1 What is Client Mode

Client Mode allows viewing data for specific organizations/clients when managing multiple entities.

### 15.2 Client Selector

Located in header:
- Dropdown showing current client
- List of available clients
- Click to switch

📸 **Screenshot: Client selector dropdown**
*Path: /screenshots/client-selector.png*

### 15.3 Switching Clients

**Steps:**
1. Click client selector dropdown
2. Select client from list
3. Dashboard reloads with client-specific data

**What filters:**
- Alerts
- Tickets
- Agents
- Assets
- Compliance data
- Reports

### 15.4 Client Information

When client selected, header shows:
- Client name
- Client description
- Active status

📸 **Screenshot: Dashboard with client selected**
*Path: /screenshots/client-mode-active.png*

### 15.5 All Clients View

Select "All Clients" to see:
- Aggregated data across all organizations
- Combined metrics
- Overall statistics

💡 **Note**: Availability depends on your permissions.

---

## 16. Attack Visualization

### 16.1 Interactive Globe

The 3D globe visualization shows real-time attacks:
- Source countries (where attacks originate)
- Target countries (where attacks land)
- Attack paths (animated arcs)

📸 **Screenshot: 3D globe with attack paths**
*Path: /screenshots/globe-visualization.png*

### 16.2 Globe Controls

**Mouse interactions:**
- **Left-click + Drag**: Rotate globe
- **Scroll**: Zoom in/out
- **Click country**: View statistics
- **Auto-rotate**: Toggle on/off

### 16.3 Attack Path Animation

Animated arcs show:
- Attack direction (source → target)
- Attack volume (thickness of arc)
- Attack type (color coding)
- Real-time updates

### 16.4 Fullscreen Mode

**Steps:**
1. Click fullscreen icon on map
2. Opens dedicated view in new window
3. Ideal for monitoring displays
4. Press ESC to exit

📸 **Screenshot: Fullscreen threat map**
*Path: /screenshots/fullscreen-map.png*

### 16.5 Map Filters

Filter displayed attacks by:
- Time range
- Severity
- Source country
- Target country

---

## 17. Alert Severity Classification

### 17.1 Understanding Severity Levels

Alerts classified by severity score (0-15):

| Severity | Score Range | Badge | Priority |
|----------|-------------|-------|----------|
| **Critical** | 15+ | 🔴 Red | Immediate action |
| **Major** | 11-14 | 🟠 Orange | High priority |
| **Minor** | 7-10 | 🟡 Yellow | Standard priority |

### 17.2 Critical Alerts (15+)

**Examples:**
- Active intrusion detected
- Malware execution
- Data exfiltration
- Root access obtained
- Ransomware activity

**Response:**
- Investigate immediately
- Create ticket
- Escalate to senior analyst
- Document all actions

### 17.3 Major Alerts (11-14)

**Examples:**
- Multiple failed login attempts
- Suspicious network traffic
- Policy violations
- Unauthorized access attempts
- File integrity changes

**Response:**
- Investigate within 1 hour
- Create ticket if confirmed
- Monitor for escalation
- Document findings

### 17.4 Minor Alerts (7-10)

**Examples:**
- Informational events
- Low-level anomalies
- Configuration changes
- Routine access logs
- System notifications

**Response:**
- Review during shift
- Create ticket if needed
- Batch similar alerts
- Update documentation

💡 **Best Practice**: Always prioritize Critical > Major > Minor.

---

## 18. Incident Response Workflow

### 18.1 Standard IR Process

**Workflow:**
```
1. Alert Detection
   ↓
2. Triage & Analysis
   ↓
3. Ticket Creation
   ↓
4. Investigation
   ↓
5. Containment
   ↓
6. Resolution
   ↓
7. Documentation
```

### 18.2 Step 1: Alert Detection

- Monitor Alerts page
- Watch for Critical/Major badges
- Check real-time notifications
- Review alert descriptions

### 18.3 Step 2: Triage & Analysis

**Questions to ask:**
- Is this a real threat? (True/False positive)
- What is the severity?
- What assets are affected?
- Is it ongoing or historical?
- Are there related alerts?

### 18.4 Step 3: Ticket Creation

From Alert page:
1. Click "Create Ticket" on alert
2. Fill priority and category
3. Assign to yourself or team member
4. Add initial notes
5. Create ticket

### 18.5 Step 4: Investigation

**Investigation steps:**
1. Review alert details
2. Check related logs in SIEM
3. Examine affected asset
4. Check threat intelligence for IOCs
5. Correlate with other alerts
6. Document findings in ticket

### 18.6 Step 5: Containment

**Containment actions:**
- Isolate affected systems
- Block malicious IPs
- Disable compromised accounts
- Stop malicious processes
- Preserve evidence

**Update ticket status to "Investigating"**

### 18.7 Step 6: Resolution

**Resolution actions:**
- Remove threat
- Restore systems
- Update security controls
- Verify remediation
- Monitor for recurrence

**Update ticket status to "Resolved"**
- Select True/False Positive
- Add detailed resolution notes

### 18.8 Step 7: Documentation

Document in ticket:
- Timeline of events
- Actions taken
- Root cause
- Remediation steps
- Preventive measures
- Lessons learned

💡 **Best Practice**: Complete documentation before closing ticket.

---

## 19. Search & Filtering

### 19.1 Global Search

Available on most pages:
- Search bar at top of tables
- Real-time filtering
- Searches multiple fields

### 19.2 Alert Search

Search alerts by:
- Alert description
- Hostname
- Agent name
- IP address
- Rule name

**Example:** Type "failed login" to find authentication failures

### 19.3 Ticket Search

Search tickets by:
- Ticket number (TKT-001234)
- Title
- Description
- Tags
- Creator name

**Example:** Type "malware" to find malware-related tickets

### 19.4 Asset Search

Search assets by:
- Asset name
- Asset tag
- IP address
- Owner name
- Location

### 19.5 Advanced Filters

**Filter combinations:**
- Severity + Date Range
- Status + Priority
- Client + Category

**Example:** Critical alerts from last 24 hours for Client ABC

📸 **Screenshot: Advanced filter panel**
*Path: /screenshots/advanced-filters.png*

### 19.6 Saving Filter Presets

Common filter combinations:
- My Open Tickets
- Critical Alerts Today
- Unassigned High Priority
- Resolved This Week

💡 **Tip**: Use filters to focus on your responsibilities.

---

## 20. User Profile Settings

### 20.1 Accessing Profile

Click your name in header → **Profile Settings**

📸 **Screenshot: Profile settings page**
*Path: /screenshots/profile-settings.png*

### 20.2 Profile Information

View and edit:
- **Username**: Your login name
- **Display Name**: How your name appears
- **Email**: Contact email
- **Role**: Your assigned role (view only)
- **Organization**: Your org/client (view only)

### 20.3 Updating Profile

1. Click **"Edit Profile"**
2. Modify allowed fields
3. Click **"Save Changes"**
4. Confirmation message appears

### 20.4 Viewing Permissions

View your permissions:
- Pages you can access
- Actions you can perform
- Data you can view

📸 **Screenshot: Permissions list**
*Path: /screenshots/user-permissions.png*

---

## 21. Notification Settings

### 21.1 Accessing Notifications

Click **Settings** → **Notification Settings**

Configure:
- Email notifications
- In-app notifications
- Alert thresholds
- Frequency

📸 **Screenshot: Notification settings**
*Path: /screenshots/notification-settings.png*

### 21.2 Email Notifications

Toggle email alerts for:
- Critical alerts
- Ticket assignments
- Ticket status changes
- Daily summaries
- Weekly reports

### 21.3 In-App Notifications

Configure dashboard notifications for:
- New critical alerts
- Ticket assignments
- Mentions in comments
- System announcements

### 21.4 Alert Thresholds

Set notification triggers:
- Critical alert count exceeds X
- Disconnected agents > Y
- Ticket SLA approaching
- Compliance drops below Z%

### 21.5 Notification Frequency

Choose delivery frequency:
- **Real-time**: Instant notifications
- **Hourly digest**: Batched every hour
- **Daily digest**: Once per day summary
- **Weekly digest**: Weekly summary

💡 **Tip**: Use hourly digest to reduce notification fatigue.

---

## 22. Dark Mode & Themes

### 22.1 Enabling Dark Mode

**Toggle dark mode:**
1. Click user menu in header
2. Toggle **"Dark Mode"** switch
3. Theme changes immediately

Or:

**In Settings:**
1. Go to Settings → General
2. Find "Theme" option
3. Select **Light** or **Dark**

📸 **Screenshot: Theme toggle**
*Path: /screenshots/theme-toggle.png*

### 22.2 Dark Mode Benefits

- Reduced eye strain during long shifts
- Better for low-light environments
- Lower screen brightness
- Modern appearance

### 22.3 Theme Persistence

- Theme preference saved per user
- Applied across all pages
- Maintained after logout/login

📸 **Screenshot: Dashboard in dark mode**
*Path: /screenshots/dark-mode-dashboard.png*

---

## 23. Password Management

### 23.1 Changing Your Password

**Steps:**
1. Click user menu → **Change Password**
2. Enter **Current Password**
3. Enter **New Password**
4. Confirm **New Password**
5. Click **"Update Password"**
6. Success message confirms change

📸 **Screenshot: Change password form**
*Path: /screenshots/change-password.png*

### 23.2 Password Requirements

New password must have:
- Minimum 8 characters
- One uppercase letter
- One lowercase letter
- One number
- One special character (@#$%^&*)

### 23.3 Password Best Practices

✅ **Do:**
- Use unique password
- Change every 90 days
- Use password manager
- Make it complex

❌ **Don't:**
- Reuse old passwords
- Share password
- Write it down
- Use common words

### 23.4 Password Reset (Forgot Password)

If you forget password:
1. Click "Forgot Password?" on login
2. Enter your email
3. Check email for reset link
4. Click link (valid 1 hour)
5. Create new password

⚠️ **Security**: Reset links expire after 1 hour.

---

## 24. Troubleshooting Guide

### 24.1 Cannot Login

**Problem:** Login fails

**Solutions:**
1. Verify username/email is correct
2. Check password (case-sensitive)
3. Ensure Caps Lock is OFF
4. Try "Forgot Password" if needed
5. Clear browser cache
6. Try different browser
7. Contact administrator if persists

### 24.2 Page Not Loading

**Problem:** Dashboard page won't load

**Solutions:**
1. Check internet connection
2. Refresh page (F5 or Ctrl+R)
3. Clear browser cache
4. Try incognito/private mode
5. Disable browser extensions
6. Update browser to latest version

### 24.3 Alerts Not Showing

**Problem:** Alerts page is empty

**Solutions:**
1. Check if filters are applied (reset filters)
2. Verify client selection (if in client mode)
3. Click "Refresh" button
4. Check with administrator
5. Verify Wazuh integration is active

### 24.4 Cannot Create Ticket

**Problem:** Ticket creation fails

**Solutions:**
1. Check required fields are filled
2. Verify you have permission
3. Check if alert already has ticket
4. Try refreshing page
5. Contact administrator

### 24.5 Dashboard Data Not Updating

**Problem:** Metrics not refreshing

**Solutions:**
1. Check "Last Updated" timestamp
2. Refresh browser page
3. Check internet connection
4. Verify session hasn't expired
5. Check SIEM connection status

### 24.6 Session Expired

**Problem:** Logged out unexpectedly

**Solutions:**
1. Login again
2. Check if inactive > 8 hours
3. Keep dashboard active
4. Enable "Remember Me" if available

### 24.7 Slow Performance

**Problem:** Dashboard is slow

**Solutions:**
1. Close unused browser tabs
2. Clear browser cache
3. Check internet speed
4. Reduce date range on reports
5. Disable browser extensions
6. Use recommended browser

### 24.8 Getting Support

**If issues persist:**
1. Note exact error message
2. Take screenshot
3. Note what you were doing
4. Contact SOC lead or administrator
5. Provide details for faster resolution

---

## 25. Best Practices for SOC Analysts

### 25.1 Daily Routine

**Shift Start:**
1. Login and verify session
2. Check overnight alerts (if coming on shift)
3. Review critical/major alerts
4. Check assigned tickets
5. Review threat intelligence feed
6. Check SIEM connection status
7. Note any disconnected agents

**During Shift:**
1. Monitor alerts page continuously
2. Triage new alerts within 15 minutes
3. Create tickets for confirmed incidents
4. Update ticket status regularly
5. Collaborate with team on investigations
6. Document all actions

**Shift End:**
1. Update all open tickets
2. Brief incoming analyst
3. Document pending investigations
4. Escalate unresolved critical items
5. Log out

### 25.2 Alert Triage

**Priority order:**
1. **Critical** first - immediate action
2. **Major** second - within 1 hour
3. **Minor** third - when available

**Triage checklist:**
- [ ] Review alert description
- [ ] Check affected asset
- [ ] Verify severity is accurate
- [ ] Check for related alerts
- [ ] Cross-reference with threat intel
- [ ] Determine true/false positive
- [ ] Create ticket if needed
- [ ] Document decision

### 25.3 Ticket Management

**Best practices:**
- Create tickets for all confirmed incidents
- Assign tickets promptly
- Update status as work progresses
- Add detailed notes throughout
- Close tickets with proper resolution
- Link related tickets

### 25.4 Investigation Tips

**Effective investigation:**
1. Gather all relevant alerts
2. Check SIEM for context
3. Review asset history
4. Check threat intelligence
5. Document timeline
6. Preserve evidence
7. Follow IR playbooks
8. Ask senior analyst if unsure

### 25.5 Communication

**Team collaboration:**
- Use ticket comments for updates
- Tag team members when needed
- Escalate unclear situations
- Share findings with team
- Brief incoming shift properly
- Document tribal knowledge

### 25.6 Documentation

**What to document:**
- Initial observations
- Investigation steps taken
- Findings and conclusions
- Actions performed
- Root cause (if identified)
- Remediation steps
- Lessons learned

**Documentation tips:**
- Write clearly and concisely
- Include timestamps
- Note evidence locations
- Use proper terminology
- Be thorough but efficient

### 25.7 Continuous Learning

**Stay current:**
- Review threat intelligence daily
- Learn from resolved incidents
- Attend team meetings
- Study new attack techniques
- Practice with past incidents
- Ask questions
- Share knowledge

### 25.8 Avoiding Burnout

**Self-care:**
- Take scheduled breaks
- Don't skip meals
- Stay hydrated
- Use dark mode for night shifts
- Rotate tasks if possible
- Ask for help when needed
- Report concerns to supervisor

💡 **Remember**: Quality over quantity. Better to handle fewer alerts thoroughly than many alerts superficially.

---

## 26. Glossary

### Security Terms

**Alert**: Notification of a security event detected by monitoring systems

**Agent**: Software installed on systems to collect security data and logs

**Asset**: Any hardware, software, or data that has value to the organization

**Compliance**: Adherence to security standards and regulatory requirements

**Critical**: Highest severity level requiring immediate action

**CVE**: Common Vulnerabilities and Exposures - standardized vulnerability identifiers

**False Positive**: Alert triggered incorrectly, not an actual security issue

**IDS/IPS**: Intrusion Detection/Prevention System

**Incident**: Confirmed security event requiring response

**IOC**: Indicator of Compromise - evidence of potential security breach

**Major**: High severity alert requiring priority attention

**Malware**: Malicious software (viruses, trojans, ransomware, etc.)

**Minor**: Lower severity alert for monitoring

**Risk**: Potential for loss or damage from a threat

**SIEM**: Security Information and Event Management system

**SOC**: Security Operations Center

**Ticket**: Case or work item for tracking incident response

**Threat**: Any circumstance or event with potential to cause harm

**Triage**: Process of assessing and prioritizing alerts

**True Positive**: Valid alert indicating actual security issue

**Vulnerability**: Weakness that could be exploited by threats

**Wazuh**: Open-source security monitoring platform

### Dashboard Terms

**Client Mode**: View data for specific organization in multi-tenant setup

**Dashboard**: Main overview page showing key metrics

**Filter**: Narrow down displayed data based on criteria

**Refresh**: Reload current data

**Resolution**: Final outcome and actions taken for incident

**Severity**: Level of importance/danger of an alert

**Status**: Current state (Open, Investigating, Resolved)

**Timestamp**: Date and time when event occurred

---

## 27. FAQ

### General Questions

**Q: How often does the dashboard update?**
A: The main dashboard refreshes every 5 seconds. Alerts and tickets require manual refresh.

**Q: How long do sessions last?**
A: Sessions expire after 8 hours of inactivity. Activity extends the session automatically.

**Q: Can I access the dashboard on mobile?**
A: Yes, but desktop/laptop provides better experience. Minimum width: 768px.

**Q: What browsers are supported?**
A: Chrome 90+, Firefox 88+, Safari 14+, Edge 90+. Chrome recommended.

### Alert Questions

**Q: What does "Critical" mean?**
A: Severity level 15+, requires immediate investigation and response.

**Q: Can I delete false positive alerts?**
A: No, but mark tickets as "False Positive" when resolving.

**Q: Why can't I create a ticket for an alert?**
A: Ticket may already exist for that alert. Check "Ticket Created" status.

**Q: How long are alerts stored?**
A: Retention depends on system configuration. Typically 90 days.

### Ticket Questions

**Q: Can I reopen a resolved ticket?**
A: No. Create new ticket if issue recurs and reference old ticket.

**Q: Who can I assign tickets to?**
A: Any active user in your organization with appropriate permissions.

**Q: What's the difference between priority and severity?**
A: Severity is technical impact; Priority is business urgency for response.

**Q: How do I escalate a ticket?**
A: Change priority to Critical and assign to senior analyst or supervisor.

### Access Questions

**Q: Why can't I see a certain page?**
A: Your role may not have permission. Contact administrator.

**Q: How do I request additional permissions?**
A: Submit request to SOC manager or administrator.

**Q: Can I access multiple clients' data?**
A: Only if you have permissions for those clients. Use client selector.

### Technical Questions

**Q: What if the dashboard is slow?**
A: Clear cache, close unused tabs, check internet connection, reduce date ranges.

**Q: How do I report a bug?**
A: Contact administrator with details, screenshot, and steps to reproduce.

**Q: Can I export data?**
A: Yes, reports can be exported as PDF, CSV, or Excel.

**Q: Is training available?**
A: Contact your SOC manager for training materials and sessions.

---

## 28. Contact & Support

### Getting Help

**For Technical Issues:**
- Contact your SOC Lead or Supervisor
- Submit ticket to IT Support
- Email: support@your-organization.com (replace with actual)

**For Account Issues:**
- Password resets: Use "Forgot Password" on login page
- Access requests: Contact SOC Manager
- Permission issues: Contact Administrator

**For Training:**
- New user onboarding: Contact SOC Manager
- Additional training: Request from supervisor
- Documentation: This user manual

### Escalation Path

**Level 1**: SOC Analyst (You)
**Level 2**: Senior SOC Analyst
**Level 3**: SOC Lead/Manager
**Level 4**: Security Operations Manager

### Best Practices for Requesting Help

**Include in your request:**
1. Your username
2. Description of issue
3. What you were trying to do
4. Error message (exact text)
5. Screenshot (if applicable)
6. Browser and version
7. When issue started

### Emergency Contacts

**For Critical Security Incidents:**
- Escalate immediately to SOC Lead
- Follow incident response procedures
- Document all actions
- Do not delay for minor issues

---

**End of User Manual**

**Version:** 1.0
**Last Updated:** October 2025
**Maintained by:** SOC Operations Team

*This manual covers the core features for SOC analysts and end users. For administrative functions, system configuration, or integration setup, please refer to the Administrator Guide.*

---

## Document Revision History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | October 2025 | Initial release | SOC Team |

---

📸 **Note on Screenshots**:
All screenshot placeholders (📸) indicate where actual screenshots should be inserted for the complete manual. Screenshots should show the exact UI elements described in each section with clear annotations if needed.

---

**Feedback**: If you have suggestions for improving this manual, please contact your SOC Manager.
