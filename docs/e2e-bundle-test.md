# End-to-End YARA Bundle Delivery & Activation Test

This document describes the complete flow for signed YARA bundle management across xdr-defense and xdr-agent.

## Architecture Overview

1. **Rule Creation** (xdr-defense UI) → Rules stored in TypeScript Map (builtin + custom)
2. **Bundle Building** (xdr-defense backend) → Ed25519-signed manifest + rule files
3. **Bundle Delivery** (agent pulls via HTTP) → Agent verifies signature, validates rules
4. **Activation** (agent) → Atomic switch of rule files, reload detection engine
5. **Detection** (agent telemetry) → YARA scans emit alerts to OpenSearch

## Prerequisites

### 1. Configure Signing Keys

On the xdr-defense system, generate an Ed25519 key pair:

```bash
# Generate Ed25519 private key seed (32 bytes, base64)
openssl pkey -in <(openssl genpkey -algorithm Ed25519) -format der -pubout -outform der | base64 -w0

# Or use Node.js crypto:
node -e "const c = require('crypto'); const k = c.generateKeyPairSync('ed25519'); console.log(k.privateKey.export({format: 'der', type: 'pkcs8'}).toString('base64'))"
```

Export private key for xdr-defense signing:

```bash
export XDR_DEFENSE_SIGNING_PRIVATE_KEY_B64="<base64-encoded-32-byte-seed>"
```

Export public key for xdr-agent verification:

```bash
export XDR_DEFENSE_SIGNING_PUBLIC_KEY_B64="<base64-encoded-32-byte-public-key>"
```

### 2. Setup OpenSearch (Optional for Testing Simulation)

If testing the simulation panel:

```bash
docker run -d \
  -e "OPENSEARCH_JAVA_OPTS=-Xms512m -Xmx512m" \
  -e OPENSEARCH_INITIAL_ADMIN_PASSWORD=YourPassword123 \
  -p 9200:9200 \
  opensearchproject/opensearch:latest
```

## Test Workflow

### Step 1: Create Custom YARA Rule via UI

1. Navigate to xdr-defense UI → **YARA Rules** tab
2. Fill in:
   - **Name**: `test_suspicious_bash`
   - **Severity**: `high`
   - **Tags**: `test, linux, shell`
   - **Content**:
     ```yara
     rule test_suspicious_bash {
       strings:
         $s1 = "/bin/bash" nocase
       condition:
         $s1
     }
     ```
3. Click **Add Rule** → Should show success

### Step 2: Validate Rule (Optional)

1. Go to **Testing** tab
2. Paste the rule content
3. Enter **Sample Text**: `/bin/bash -c whoami`
4. Click **Run Test** → Should show `validation.status: "valid"`

### Step 3: Build Signed Bundle

1. Go to **Bundle Status & Rollout** tab
2. You should see "No bundle generated yet" initially
3. Click **Build & Sign Bundle** → Should show:
   - Success banner: "Bundle built and signed: version X"
   - Updated bundle metadata showing:
     - Bundle Version
     - Generated timestamp
     - Total Rules (builtin + your custom rule)
     - Enabled Rules

### Step 4: Verify Bundle Contents

1. Click **View Manifest** → Shows bundle structure:
   ```json
   {
     "manifest_version": 1,
     "policy_id": "global-default",
     "bundle_version": 1,
     "generated_at": "2026-03-22T10:30:45.123Z",
     "signing_alg": "ed25519",
     "rule_count": 3,
     "active_checksums": 3
   }
   ```

### Step 5: Agent Fetches & Verifies Bundle

On the agent side (simulated test):

```bash
# 1. Agent fetches bundle from xdr-defense
BUNDLE_JSON=$(curl -s http://localhost:5602/api/xdr-defense/yara/bundle?policy_id=global-default)

# 2. Extract signature & payload
SIGNATURE=$(echo $BUNDLE_JSON | jq -r .signature_base64)
PAYLOAD=$(echo $BUNDLE_JSON | jq -r .signed_payload_base64)

# 3. Verify Ed25519 signature using public key
echo $PAYLOAD | base64 -d > payload.json
echo $SIGNATURE | base64 -d > signature.bin
cat $PUBLIC_KEY | openssl dgst -sha256 -verify <(openssl pkey -pubin -in /dev/stdin < $PUBLIC_KEY) -signature signature.bin payload.json
# Output: "Verified OK" if signature is correct
```

### Step 6: Agent-Side Activation

In the running xdr-agent process (internal flow):

```
Service loop tick on defensePostureTicker:
├─ syncDefensePosture()  ← Fetch posture (toggles including malware.yara_detection)
├─ ApplyDefensePosture() ← Apply to runtime config
└─ syncYaraBundle()      ← New: Fetch & activate
    ├─ Fetch HTTP GET /api/xdr-defense/yara/bundle
    ├─ Verify signature via Ed25519 (crypto/ed25519)
    ├─ Validate rule syntax (lexical check)
    ├─ Verify rule content checksums (SHA256)
    ├─ Save rules to /etc/xdr-agent/rules/malware/yara/ (atomic)
    ├─ Save bundle metadata
    └─ ReloadMalwareRules() ← Hot-reload into detection engine
```

Agent logs:
```
INFO: YARA bundle activated: policy_id=global-default bundle_version=1 enabled_rules=3
INFO: malware rules reloaded from disk
```

### Step 7: Trigger Detection

1. Create a file with your test rule match pattern:
   ```bash
   echo "/bin/bash" > /tmp/test-yara-match.txt
   chmod +x /tmp/test-yara-match.txt
   ```

2. Trigger agent to scan (depends on telemetry source; file.NewProcessCollector, FIM, etc.)

3. If `malware.yara_detection` is enabled + executes, should emit alert:
   ```json
   {
     "event.module": "detection.malware",
     "event.type": "alert",
     "rule.id": "test_suspicious_bash",
     "rule.name": "test_suspicious_bash",
     "method": "yara-x",
     "file.sha256": "<hash>",
     "event.action": "alert" // or "block" in prevent mode
   }
   ```

### Step 8: Verify Alert in OpenSearch

Query alerts index:

```bash
curl -X GET "localhost:9200/.xdr-agent-alerts*/_search" -H "Content-Type: application/json" -d '{
  "query": {
    "match": {
      "event.module": "detection.malware"
    }
  }
}'
```

Expected result:
```json
{
  "hits": {
    "hits": [
      {
        "_source": {
          "event.module": "detection.malware",
          "rule.id": "test_suspicious_bash",
          "rule.name": "test_suspicious_bash",
          "method": "yara-x",
          "file.path": "/tmp/test-yara-match.txt",
          ...
        }
      }
    ]
  }
}
```

## Error Scenarios

### Bundle Signature Fails

**Cause**: Public key mismatch or corrupted bundle

**Agent Log**:
```
warning: failed to activate YARA bundle: bundle signature verification failed
```

**Action**: Verify `XDR_DEFENSE_SIGNING_PUBLIC_KEY_B64` matches the key used to sign

### Rule Validation Fails

**Cause**: Broken YARA rule syntax

**Agent Log**:
```
warning: failed to activate YARA bundle: rule content validation failed: rule test_rule validation failed: missing 'condition:' section
```

**Action**: Fix rule syntax in xdr-defense UI → Rebuild bundle

### Rule Checksum Mismatch

**Cause**: Rule file corrupted in transit

**Agent Log**:
```
warning: failed to activate YARA bundle: rule checksum verification failed: rule test_rule.yar checksum mismatch: expected abc123, got def456
```

**Action**: Network issue; agent will retry on next posture sync tick

## Atomic Activation Guarantee

If bundle activation fails at **any step**, the agent:

1. Keeps previous active bundle intact
2. Logs detailed error
3. Retries on next DefensePostureTicker tick (default: 60 seconds)

This ensures no broken rules ever reach the detection engine.

## Safe Deletion

- **Builtin rules**: Cannot be deleted; can only be disabled
- **Custom rules**: Can be deleted anytime
- **Effect**: Next bundle build excludes deleted rules

Example:

```
Define rule → Validate → Toggle enable/disable → Build bundle
             ↓
Delete custom rule → Build bundle (rule no longer in manifest)
             ↓
Agent fetches new bundle → Removes old rule file from disk
```

## SIGMA Integration Path (Not Implemented Yet)

Instead of implementing SIGMA rules in the agent, use OpenSearch Security Analytics:

1. Export agent YARA detections to OpenSearch `detection.malware` index
2. Create Security Analytics Detector with condition: `event.module == "detection.malware"`
3. Define correlation rules over time windows (e.g., "5 YARA hits from same user within 10 minutes")
4. Emit findings that feed into response playbooks

This keeps detection logic centralized in OpenSearch while using agent for performant single-event matching.

---

**Last Updated**: 2026-03-22  
**Test Status**: Ready for end-to-end validation
