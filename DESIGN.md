# ProofOfControl Court — System Design & Architecture Specification

## 1. Asymmetric Equivalence Principle

ProofOfControl Court implements **Graduated Asymmetric Equivalence** to guarantee consensus safety without LLM formatting deadlocks:

```
Consensus Payload
├── Strict Part (100% Deterministic Agreement Required):
│   ├── http_error: bool (Must match exact network status)
│   ├── payload_found: bool (Must match exact content presence)
│   ├── detected_nonce: str (Exact nonce extracted from payload, or "NONE")
│   ├── is_nonce_exact_match: bool (Strictly true iff detected_nonce == expected_nonce)
│   ├── is_claimant_exact_match: bool (Strictly true iff expected_claimant in body)
│   ├── verified: bool (True iff no http_error, payload_found, and exact matches)
│   └── failure_code: str ("NONE", "HTTP_ERROR", "PAYLOAD_NOT_FOUND", "NONCE_MISMATCH", "CLAIMANT_MISMATCH")
└── Fuzzy Part (Bounded Tolerance Allowed):
    ├── confidence: int (Allowed tolerance ±10 points within the same outcome tier)
    └── summary: str (Audit sentence)
```

### Validator Rejection Rule:
Validators independently parse the live HTTP response and MUST reject the leader's proposal if:
1. `detected_nonce` does not strictly match the exact nonce string present in the live HTTP body (or 'NONE' if absent).
2. `is_nonce_exact_match` is true when `detected_nonce != expected_nonce`.
3. `is_claimant_exact_match` is true when `expected_claimant` is not present in `extracted_body`.
4. `verified` is true when `failure_code != 'NONE'` or any mismatch exists.
5. The proposed `failure_code` is inconsistent with the live HTTP body evidence in **EITHER direction**.
6. The proposed `payload_found` is `false` when valid challenge payload data exists on the target URL.
7. The proposed confidence score deviates by more than $\pm 10$ points.

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
