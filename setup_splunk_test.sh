#!/bin/bash
#
# Splunk HEC Test Environment Setup
# ==================================
# This script creates a Docker-based Splunk instance for testing
# the NX-OS Compliance Checker Splunk HEC integration.
#
# Usage: ./setup_splunk_test.sh
#
# After running, Splunk will be available at:
#   - Web UI: http://localhost:8000 (admin/TestPassword123!)
#   - HEC:    http://localhost:8088
#

set -e

# Configuration
SPLUNK_PASSWORD="TestPassword123!"
SPLUNK_CONTAINER="splunk-hec-test"
SPLUNK_IMAGE="splunk/splunk:latest"
HEC_TOKEN="11111111-1111-1111-1111-111111111111"

echo "=============================================="
echo "Splunk HEC Test Environment Setup"
echo "=============================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Stop and remove existing container if it exists
if docker ps -a --format '{{.Names}}' | grep -q "^${SPLUNK_CONTAINER}$"; then
    echo "🗑️  Removing existing container..."
    docker stop ${SPLUNK_CONTAINER} 2>/dev/null || true
    docker rm ${SPLUNK_CONTAINER} 2>/dev/null || true
fi

echo "📥 Pulling Splunk image (this may take a few minutes)..."
docker pull ${SPLUNK_IMAGE}

echo "🚀 Starting Splunk container..."
docker run -d \
    --name ${SPLUNK_CONTAINER} \
    --hostname splunk \
    -p 8000:8000 \
    -p 8088:8088 \
    -p 8089:8089 \
    -e "SPLUNK_PASSWORD=${SPLUNK_PASSWORD}" \
    -e "SPLUNK_START_ARGS=--accept-license" \
    -e "SPLUNK_HEC_TOKEN=${HEC_TOKEN}" \
    ${SPLUNK_IMAGE}

echo "⏳ Waiting for Splunk to start (this takes 2-3 minutes)..."
echo "   Checking container logs..."

# Wait for Splunk to be ready
MAX_WAIT=180
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if docker logs ${SPLUNK_CONTAINER} 2>&1 | grep -q "Ansible playbook complete"; then
        echo "✅ Splunk container is ready!"
        break
    fi
    sleep 5
    WAITED=$((WAITED + 5))
    echo "   Still waiting... (${WAITED}s / ${MAX_WAIT}s)"
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "⚠️  Timeout waiting for Splunk. Check logs with: docker logs ${SPLUNK_CONTAINER}"
fi

# Wait a bit more for services to stabilize
sleep 10

echo ""
echo "🔧 Configuring HEC..."

# Enable HEC and create token using Splunk REST API
docker exec ${SPLUNK_CONTAINER} bash -c "
    # Enable HEC globally
    /opt/splunk/bin/splunk http-event-collector enable -uri https://localhost:8089 -auth admin:${SPLUNK_PASSWORD}
    
    # Create the HEC token
    /opt/splunk/bin/splunk http-event-collector create nxos_compliance \
        -uri https://localhost:8089 \
        -auth admin:${SPLUNK_PASSWORD} \
        -disabled 0 \
        -index main \
        -indexes main,network_compliance \
        -sourcetype nxos:compliance
"

# Create network_compliance index
echo "📁 Creating network_compliance index..."
docker exec ${SPLUNK_CONTAINER} bash -c "
    /opt/splunk/bin/splunk add index network_compliance \
        -auth admin:${SPLUNK_PASSWORD} || echo 'Index may already exist'
"

# Get the actual HEC token
echo ""
echo "🔑 Retrieving HEC token..."
ACTUAL_TOKEN=$(docker exec ${SPLUNK_CONTAINER} bash -c "
    /opt/splunk/bin/splunk http-event-collector list \
        -uri https://localhost:8089 \
        -auth admin:${SPLUNK_PASSWORD} 2>/dev/null | grep -A1 'nxos_compliance' | grep 'token=' | cut -d'=' -f2
")

if [ -z "$ACTUAL_TOKEN" ]; then
    ACTUAL_TOKEN="Check Splunk UI: Settings > Data Inputs > HTTP Event Collector"
fi

echo ""
echo "=============================================="
echo "✅ Splunk HEC Test Environment Ready!"
echo "=============================================="
echo ""
echo "Splunk Web UI:"
echo "  URL:      http://localhost:8000"
echo "  Username: admin"
echo "  Password: ${SPLUNK_PASSWORD}"
echo ""
echo "Splunk HEC:"
echo "  URL:      http://localhost:8088"
echo "  Token:    ${ACTUAL_TOKEN}"
echo ""
echo "Test the compliance checker with:"
echo "  python nxos_compliance_checker_v2_5_splunk.py config.txt \\"
echo "      --splunk-url http://localhost:8088 \\"
echo "      --splunk-token ${ACTUAL_TOKEN} \\"
echo "      --splunk-no-verify-ssl"
echo ""
echo "View events in Splunk:"
echo "  index=main OR index=network_compliance sourcetype=\"nxos:compliance\""
echo ""
echo "Stop the container:"
echo "  docker stop ${SPLUNK_CONTAINER}"
echo ""
echo "Remove the container:"
echo "  docker rm ${SPLUNK_CONTAINER}"
echo "=============================================="
