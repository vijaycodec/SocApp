# Report Generation Verification Checklist

## What to Check in Backend Console Logs:

When you generate a report, you should see these logs:

### 1. Organization Selection
```
🔍 Client user <username> organization credentials check:
  name: '<Organization Name>'
  wazuh_ip: '<IP>'
  indexer_ip: '<IP>'
✅ Client credentials set for <username> from organization <Organization Name>
```

### 2. Report Generation Start
```
========== GENERATING REPORT ==========
Organization: <Organization Name>
Organization ID: <org_id>
Client Name: <username>
Frequency: weekly
Date range: <start> to <end>
Wazuh Host: https://<org_wazuh_ip>:55000
Indexer Host: https://<org_indexer_ip>:9200
=======================================
```

### 3. Real Alerts Fetched
```
✅ Fetched <N> REAL alerts from Wazuh Indexer for <Organization Name>
   Sample alert: <Alert Description> (Severity: <N>, Time: <timestamp>)
```
OR if no alerts:
```
⚠️ No alerts found in the specified time range
```

### 4. Real Agents Fetched
```
✅ Fetched <N> agents from Wazuh API for <Organization Name>
   Active: <N>, Disconnected: <N>, Never Connected: <N>
```

### 5. Real SCA Data Fetched
```
Fetching SCA compliance data for <Organization Name>...
SCA data fetched: <N> policies, <N> checks, <N>% score
SCA per agent: <N> agents with SCA data
✅ SCA Data: Overall Score: <N>%, Total Checks: <N>, Agents with SCA: <N>
```

## How to Verify:

1. **Check the logs match your selected organization**
   - Organization name should match what you selected
   - Wazuh/Indexer IPs should be YOUR organization's IPs (not another org's)

2. **Verify real data**
   - Alert count > 0 means real alerts (or genuinely no alerts in time range)
   - Sample alert shows actual Wazuh alert description
   - Agent count matches your actual infrastructure
   - SCA scores are real percentages (not 87.5% placeholder)

3. **Open the generated PDF**
   - Cover page shows only organization name
   - Alerts table has real descriptions and timestamps
   - Agent scores show actual compliance percentages
   - All data is consistent with what you see in Wazuh dashboard

## Red Flags (Dummy Data):
- ❌ Organization name is generic ("Organization" or "Client")
- ❌ Alert descriptions are too generic
- ❌ SCA score is exactly 87.5% (that was the old placeholder)
- ❌ No sample alert shown in logs
- ❌ Wazuh/Indexer IPs don't match your organization
