# ProofOfControl Court — System Design & Architecture Specification

## 1. Asymmetric Equivalence Principle

ProofOfControl Court implements **Graduated Asymmetric Equivalence** to guarantee consensus safety without LLM formatting deadlocks:

```
Consensus Payload
├── Strict Part (100% Deterministic Agreement Required):
│   ├── http_error: bool (Must match exact network status)
│   ├── payload_found: bool (Must match exact content presence)
│   └── failure_code: str ("NONE", "HTTP_404_OR_MISSING", "NONCE_MISMATCH")
└── Fuzzy Part (Bounded Tolerance Allowed):
    └── confidence: int (Allowed tolerance ±10 points within the same outcome tier)
```

### Validator Rejection Rule:
Validators independently parse the live HTTP response and MUST reject the leader's proposal if:
1. The proposed `failure_code` is inconsistent with the live HTTP body evidence in **EITHER direction**.
2. The proposed `payload_found` is `false` when valid challenge payload data exists on the target URL.
3. The proposed `extracted_body` does not contain the actual HTTP response content.
4. The proposed confidence score deviates by more than $\pm 10$ points.

---

## 2. State Machine Transitions

```
                    +------------------------------------+
                    |              PENDING               |
                    | (Challenge created, nonce assigned)|
                    +-----------------+------------------+
                                      |
                      [ Claimant calls verify_control ]
                                      |
                 +--------------------+--------------------+
                 |                                         |
     [ All checks pass:                                [ Any check fails:
       - http_error == False                             - http_error == True
       - payload_found == True                           - payload_found == False
       - nonce in body                                   - nonce missing
       - claimant in body ]                              - claimant mismatch ]
                 |                                         |
                 v                                         v
      +---------------------+                   +---------------------+
      |      VERIFIED       |                   |       FAILED        |
      | (verified = True)   |                   | (verified = False)  |
      | (failure_code=NONE) |                   | (failure_code=...)  |
      +---------------------+                   +---------------------+
```

---

## 3. Strict Input Sanitization & Normalization

1. **Protocol Stripping**: Automatically strips `https://` and `http://` from `target_id`.
2. **Path Sanitization**:
   - `DOMAIN`: Rejects hostnames containing slashes (`/`), spaces, or invalid TLD characters (`[ERR_VAL_01]`).
   - `GITHUB_REPO`: Enforces strict two-part `owner/repo` syntax (`[ERR_VAL_02]`).
3. **Address Normalization**: All Ethereum addresses are lowercased and stripped of quotation marks to prevent EIP-55 checksum character mismatches.
