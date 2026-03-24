# Signed YARA Bundle Contract

## Overview

All YARA rule updates from xdr-defense to xdr-agent are delivered as **signed bundles**. Each bundle is immutable, versioned, and includes:
- Rule manifest (list of rules, metadata, signatures)
- Individual rule files (`.yar`, `.yara`)
- Bundle signature (Ed25519 over manifest)
- Public key certificate for verification

## Bundle Structure

```
SignedYaraBundle {
  manifest: RuleManifest
  bundle_signature: string (base64 ed25519 signature)
  public_key_cert: string (base64 ed25519 public key PEM or raw)
}

RuleManifest {
  version: string (semver, e.g., "2026.03.22.5")
  created_at: string (ISO 8601 timestamp)
  rule_sources: [
    {
      id: string (uuid or slug)
      name: string
      description: string
      source: "builtin" | "custom"
      enabled: bool
      severity: "low" | "medium" | "high" | "critical"
      file_path: string (relative to /etc/xdr-agent/rules/malware/yara)
      checksum_sha256: string (of the .yar/.yara file content)
      tags: [string]
      module_scope: [string] (e.g., ["elf", "hash", "math"] - allowlist of permitted YARA-X modules used in this rule)
      mitre_tactics: [string] (e.g., ["T1036", "T1027"])
      status: "draft" | "validated" | "active"
      custom_metadata: object (user-defined, e.g., { "owner": "team-name", "ticket": "SEC-1234" })
    }
  ]
  enforcement_summary: {
    total_rules: int
    enabled_rules: int
    validation_errors: [string] (if any compilation failed; stored for audit)
  }
}
```

## HTTP Payload (Agent Polls)

**Request:** `GET /api/xdr-defense/signed-artifacts/yara-bundle`

**Response:**
```json
{
  "bundle": {
    "manifest": { ... RuleManifest ... },
    "bundle_signature": "base64-encoded-ed25519-signature",
    "public_key_cert": "-----BEGIN PUBLIC KEY-----\n...base64...\n-----END PUBLIC KEY-----"
  },
  "version": "2026.03.22.5",
  "download_url": "/api/xdr-defense/signed-artifacts/yara-bundle/files"
}
```

**File Download:**  
`GET /api/xdr-defense/signed-artifacts/yara-bundle/files?id=<rule-id>`  
Returns gzipped `.yar`/`.yara` file with Etag for caching.

## Agent-Side Verification

1. **Signature check**: Verify bundle_signature over manifest using public_key_cert.
2. **Rule compile**: For each enabled rule, attempt YARA-X compile with module scope allowlist.
3. **Safe activation**: 
   - If all rules compile, activate bundle atomically.
   - If any rule fails to compile, reject entire bundle and log error.
   - Keep previous bundle active (graceful fallback).
4. **ACK posture**: Agent sends posture ACK with bundle version to xdr-defense.

## Signatures & Key Management

- **Algorithm:** Ed25519 (deterministic, simple, no random nonce confusion)
- **Key format:** PEM (public key cert) for portability
- **Signing flow (xdr-defense):**
  1. Load private key from secure store (env variable, K8s secret, or derivation)
  2. Build RuleManifest JSON (sorted for determinism)
  3. Sign manifest bytes with private key
  4. Include public key in bundle response for agent offline fallback

## Rule Module Scope Allowlist

To prevent accidental use of untested YARA-X modules, each rule declares `module_scope`:

**Allowed (production-safe):**
- `elf` – Linux binary metadata extraction
- `hash` – SHA256/MD5 computation
- `math` – Numeric operations
- `string` – String manipulation
- `console` – Debug output (for testing only)

**Restricted (custom rules):**
- `pe` – Windows binary (custom rules disallowed until proven)
- `dotnet`, `macho`, `dex`, `crx` – Format-specific (for builtin only)

Custom rules default to `["elf", "hash", "math", "string"]` scope; admin can expand case-by-case.

## Status Transitions

```
draft -> validated -> active
           ^          |
           |__________|  (rollback after error)
```

- **draft:** Created, not yet tested
- **validated:** Compilation passed, semantic checks passed, no deploy yet
- **active:** Deployed, agents pulling and verifying
- **disabled:** Compiled and valid, but `enabled=false` → excluded from bundle

## Deletion & Cleanup

- Custom rules can be deleted by owner/admin at any time.
- Builtin rules can only be disabled (marked `enabled=false`).
- Deleted custom rules are removed from next bundle version.
- Rollback strategy: Agent keeps previous 2 bundle versions locally.

## Atomicity & Versioning

- Each bundle version is immutable; re-running the same rules produces same checksum/version.
- Version scheme: `YYYY.MM.DD.SEQUENCE` (e.g., `2026.03.22.5` = 5th bundle on March 22, 2026)
- Agent pulls latest `>=` its current version; downloads only new/changed rule files.
