# Testing Splunk HEC Integration with Docker

## Quick Start (5 minutes)

### Step 1: Start Splunk Container

```bash
# Pull and run Splunk Enterprise
docker run -d \
    --name splunk-test \
    -p 8000:8000 \
    -p 8088:8088 \
    -e "SPLUNK_PASSWORD=TestPassword123!" \
    -e "SPLUNK_START_ARGS=--accept-license" \
    splunk/splunk:latest
```

### Step 2: Wait for Splunk to Start

```bash
# Watch the logs until you see "Ansible playbook complete"
docker logs -f splunk-test

# This takes about 2-3 minutes
# Press Ctrl+C once you see "Ansible playbook complete"
```

### Step 3: Configure HEC via Web UI

1. Open **http://localhost:8000** in your browser
2. Login with `admin` / `TestPassword123!`
3. Go to **Settings → Data Inputs → HTTP Event Collector**
4. Click **Global Settings** (top right):
   - Set **All Tokens** to **Enabled**
   - Uncheck **Enable SSL** (for easier testing)
   - Click **Save**
5. Click **New Token**:
   - Name: `nxos_compliance`
   - Click **Next**
   - Source type: Select **Manual** → enter `nxos:compliance`
   - Index: Select **main** (or create `network_compliance`)
   - Click **Review** → **Submit**
6. **Copy the token value** shown on the success page

### Step 4: Test the Integration

```bash
# Test connection
python nxos_compliance_checker_v2_5_splunk.py config.txt \
    --splunk-url http://localhost:8088 \
    --splunk-token YOUR_TOKEN_HERE \
    --splunk-no-verify-ssl \
    --splunk-test-connection

# Run full compliance check with Splunk export
python nxos_compliance_checker_v2_5_splunk.py config.txt \
    --splunk-url http://localhost:8088 \
    --splunk-token YOUR_TOKEN_HERE \
    --splunk-no-verify-ssl \
    --verbose
```

### Step 5: View Results in Splunk

1. Go to **http://localhost:8000**
2. Click **Search & Reporting**
3. Enter this search:

```spl
index=main OR index=network_compliance sourcetype="nxos:compliance"
```

4. Click the green **Search** button

You should see your compliance events!

---

## Alternative: All-in-One Command Line Setup

If you prefer command line only:

```bash
# 1. Start Splunk
docker run -d --name splunk-test -p 8000:8000 -p 8088:8088 \
    -e "SPLUNK_PASSWORD=TestPassword123!" \
    -e "SPLUNK_START_ARGS=--accept-license" \
    splunk/splunk:latest

# 2. Wait for startup (about 2-3 minutes)
sleep 180

# 3. Enable HEC via REST API
docker exec splunk-test /opt/splunk/bin/splunk http-event-collector enable \
    -uri https://localhost:8089 -auth admin:TestPassword123!

# 4. Create HEC token
docker exec splunk-test /opt/splunk/bin/splunk http-event-collector create nxos_compliance \
    -uri https://localhost:8089 \
    -auth admin:TestPassword123! \
    -disabled 0 \
    -index main

# 5. List tokens to get the token value
docker exec splunk-test /opt/splunk/bin/splunk http-event-collector list \
    -uri https://localhost:8089 -auth admin:TestPassword123!
```

---

## Quick Verification Test (Without Compliance Checker)

Test HEC is working with a simple curl command:

```bash
# Replace YOUR_TOKEN with the actual token
curl -k http://localhost:8088/services/collector/event \
    -H "Authorization: Splunk YOUR_TOKEN" \
    -d '{"event": "Hello from NX-OS Compliance Checker test!", "sourcetype": "nxos:compliance"}'
```

Expected response:
```json
{"text":"Success","code":0}
```

---

## Splunk Dashboard Queries for Testing

Once data is in Splunk, try these searches:

```spl
# All compliance events
index=main sourcetype="nxos:compliance"

# Summary events only
index=main sourcetype="nxos:compliance" event_type="compliance_summary"

# Failed checks
index=main sourcetype="nxos:compliance" event_type="compliance_check" status="FAIL"

# Count by severity
index=main sourcetype="nxos:compliance" event_type="compliance_check" status="FAIL"
| stats count by severity

# Compliance score
index=main sourcetype="nxos:compliance" event_type="compliance_summary"
| table _time, hostname, percentage, grade, passed_count, failed_count
```

---

## Cleanup

```bash
# Stop the container
docker stop splunk-test

# Remove the container
docker rm splunk-test

# Remove the image (optional, saves ~2GB)
docker rmi splunk/splunk:latest
```

---

## Troubleshooting

### "Connection refused" error
- Wait longer for Splunk to start (check `docker logs splunk-test`)
- Verify port 8088 is exposed: `docker port splunk-test`

### "Invalid token" error
- Double-check the token value
- Ensure HEC is enabled globally in Splunk settings
- Make sure the token is not disabled

### "SSL certificate error"
- Use `--splunk-no-verify-ssl` flag
- Or use `http://` instead of `https://`

### No events appearing in Splunk
- Check the index name matches (default is `main`)
- Verify sourcetype: `sourcetype="nxos:compliance"`
- Try `index=*` to search all indexes
