# ProofOfControl Court — GenLayer Studio Test Log & Guide

This document provides step-by-step instructions for testing and validating **ProofOfControl Court** in GenLayer Studio.

---

## 📋 Test Plan

| Test Case | Target Type | Target ID | Expected Nonce Match | Expected Status |
|---|---|---|---|---|
| **TC-01** | `DOMAIN` | `tumhi4.github.io` | Hosted at `.well-known/genlayer-control.json` | `VERIFIED` |
| **TC-02** | `DOMAIN` | `nonexistent-site-12345.com` | 404 Missing | `FAILED` (`HTTP_404_OR_MISSING`) |
| **TC-03** | `GITHUB_REPO` | `octocat/Hello-World` | Nonce Mismatch | `FAILED` (`NONCE_MISMATCH`) |

---

## 🛠️ Step-by-Step Studio Execution

### Step 1: Deploy Contract
Deploy `ProofOfControlCourt` in GenLayer Studio:
* `operator`: `"0x5c48c6f77617fc05761433cc4019a79b47d1ec7d"`

---

### Step 2: Request Challenge (`request_challenge`)
Call `request_challenge`:
* `target_type`: `"DOMAIN"`
* `target_id`: `"tumhi4.github.io"`

**Expected Studio Output**:
```json
{
  "challenge_id": "CHALLENGE_001",
  "target_type": "DOMAIN",
  "target_id": "tumhi4.github.io",
  "claimant": "0x5c48c6f77617fc05761433cc4019a79b47d1ec7d",
  "required_nonce": "GL-CONTROL-PROOF-0x5c48c6f7-CHALLENGE_001-9482715",
  "host_url": "https://tumhi4.github.io/.well-known/genlayer-control.json"
}
```

---

### Step 3: Host File at `.well-known/genlayer-control.json`
Create and host the file `genlayer-control.json` at `https://tumhi4.github.io/.well-known/genlayer-control.json`:

```json
{
  "genlayer_proof_of_control": {
    "claimant_address": "0x5c48c6f77617fc05761433cc4019a79b47d1ec7d",
    "target_id": "tumhi4.github.io",
    "challenge_id": "CHALLENGE_001",
    "nonce": "GL-CONTROL-PROOF-0x5c48c6f7-CHALLENGE_001-9482715"
  }
}
```

---

### Step 4: Execute Verification (`verify_control`)
Call `verify_control`:
* `challenge_id`: `"CHALLENGE_001"`

---

### Step 5: Inspect Verification Result (`get_challenge`)
Call `get_challenge`:
* `challenge_id`: `"CHALLENGE_001"`

**Expected Output**:
```json
{
  "claimant": "0x5c48c6f77617fc05761433cc4019a79b47d1ec7d",
  "confidence_score": 100,
  "derived_challenge_url": "https://tumhi4.github.io/.well-known/genlayer-control.json",
  "failure_code": "NONE",
  "id": "CHALLENGE_001",
  "last_audit_summary": "PROOF OF CONTROL VERIFIED: Claimant '0x5c48c6f77617fc05761433cc4019a79b47d1ec7d' proven in control of DOMAIN 'tumhi4.github.io'. Cryptographic nonce 'GL-CONTROL-PROOF-0x5c48c6f7-CHALLENGE_001-9482715' validated in hosted payload.",
  "nonce": "GL-CONTROL-PROOF-0x5c48c6f7-CHALLENGE_001-9482715",
  "status": "VERIFIED",
  "target_id": "tumhi4.github.io",
  "target_type": "DOMAIN",
  "verified": true
}
```
