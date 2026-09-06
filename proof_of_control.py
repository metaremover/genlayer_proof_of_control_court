# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
import json
import re
from dataclasses import dataclass
from genlayer import *


@allow_storage
@dataclass
class ChallengeRecord:
    id: str
    target_type: str
    target_id: str
    claimant: str
    nonce: str
    derived_challenge_url: str
    status: str
    confidence_score: u256
    verified: bool
    failure_code: str
    last_audit_summary: str


class ProofOfControlCourt(gl.Contract):
    operator: str
    challenges: TreeMap[str, ChallengeRecord]
    next_challenge_id: u256

    def __init__(self, operator: str):
        self.operator = operator.strip().strip('"').strip("'").lower()
        # GenLayer VM automatically instantiates storage-backed TreeMaps.
        self.next_challenge_id = u256(0)

    @gl.public.write
    def request_challenge(self, target_type: str, target_id: str) -> str:
        sender = str(gl.message.sender_address).lower()
        t_type = target_type.strip().strip('"').strip("'").upper()
        t_id = target_id.strip().strip('"').strip("'").lower()

        # Sanitize target_id removing protocol prefixes if present
        if t_id.startswith("https://"):
            t_id = t_id[8:]
        elif t_id.startswith("http://"):
            t_id = t_id[7:]
        t_id = t_id.rstrip("/")

        assert t_type in ("DOMAIN", "GITHUB_REPO", "API_ENDPOINT"), \
            "[ERR_TYPE_01] target_type must be 'DOMAIN', 'GITHUB_REPO', or 'API_ENDPOINT'."

        if t_type == "DOMAIN":
            assert len(t_id) >= 3 and "." in t_id and "/" not in t_id, \
                "[ERR_VAL_01] DOMAIN target_id must be a valid hostname (e.g. 'example.com') without path slashes."
            derived_url = f"https://{t_id}/genlayer-control.json"
        elif t_type == "GITHUB_REPO":
            parts = t_id.split("/")
            assert len(parts) == 2 and len(parts[0]) > 0 and len(parts[1]) > 0, \
                "[ERR_VAL_02] GITHUB_REPO target_id must follow 'owner/repo' format (e.g. 'octocat/Hello-World')."
            derived_url = f"https://raw.githubusercontent.com/{parts[0]}/{parts[1]}/main/genlayer-control.json"
        else:  # API_ENDPOINT
            assert len(t_id) >= 3 and "." in t_id, \
                "[ERR_VAL_03] API_ENDPOINT target_id must be a valid host or host/path."
            derived_url = f"https://{t_id}/genlayer-control.json"

        c_num = int(self.next_challenge_id) + 1
        self.next_challenge_id = u256(c_num)
        c_id = "CHALLENGE_" + str(c_num).zfill(3)

        # Generate unique cryptographic challenge nonce tied to sender and challenge ID
        nonce_token = f"GL-CONTROL-PROOF-{sender[:10]}-{c_id}-{abs(hash(t_id + sender)) % 10000000:07d}"

        new_challenge = ChallengeRecord(
            id=c_id,
            target_type=t_type,
            target_id=t_id,
            claimant=sender,
            nonce=nonce_token,
            derived_challenge_url=derived_url,
            status="PENDING",
            confidence_score=u256(0),
            verified=False,
            failure_code="NONE",
            last_audit_summary=(
                f"Challenge created for {t_type} '{t_id}'. "
                f"Host JSON at '{derived_url}' containing nonce '{nonce_token}'."
            )
        )

        self.challenges[c_id] = new_challenge
        return json.dumps({
            "challenge_id": c_id,
            "target_type": t_type,
            "target_id": t_id,
            "claimant": sender,
            "required_nonce": nonce_token,
            "host_url": derived_url,
            "expected_payload": {
                "genlayer_proof_of_control": {
                    "claimant_address": sender,
                    "target_id": t_id,
                    "challenge_id": c_id,
                    "nonce": nonce_token
                }
            }
        })

    @gl.public.write
    def verify_control(self, challenge_id: str) -> None:
        assert challenge_id in self.challenges, "[ERR_STATE_01] Challenge ID does not exist."

        challenge = self.challenges[challenge_id]
        sender = str(gl.message.sender_address).lower()

        # Access Control: Only the claimant or contract operator can trigger verification
        assert sender == challenge.claimant or sender == self.operator, \
            "[ERR_AUTH_01] Unauthorized: caller must be the challenge claimant or contract operator."

        assert challenge.status == "PENDING", "[ERR_STATE_02] Challenge verification is already finalized."

        target_url = challenge.derived_challenge_url
        expected_nonce = challenge.nonce
        expected_claimant = challenge.claimant
        t_id = challenge.target_id
        t_type = challenge.target_type

        def get_input() -> str:
            try:
                web_data = gl.nondet.web.render(target_url, mode="text")
            except Exception as e:
                web_data = f"HTTP_FETCH_ERROR: {str(e)}"

            return (
                f"Official Live ProofOfControl Audit for Target URL '{target_url}':\n\n"
                f"{web_data}\n\n"
                f"Expected Target Identifier: '{t_id}'\n"
                f"Expected Claimant Wallet Address: '{expected_claimant}'\n"
                f"Expected Challenge Nonce String: '{expected_nonce}'"
            )

        task = (
            "You are a Senior Decentralized Asset Ownership & ProofOfControl Auditor.\n"
            "Parse the live rendered HTTP response provided in the input.\n\n"
            "Your job:\n"
            "1. Check if the page/payload was successfully retrieved (http_error=false). If HTTP status != 200, network error, or fetch failed, set http_error=true, payload_found=false, detected_nonce=\"NONE\", is_nonce_exact_match=false, is_claimant_exact_match=false, verified=false, failure_code=\"HTTP_ERROR\", confidence=0.\n"
            "2. Extract the exact body text or JSON payload from the response (extracted_body). If the body is empty, missing, or malformed, set payload_found=false, detected_nonce=\"NONE\", is_nonce_exact_match=false, is_claimant_exact_match=false, verified=false, failure_code=\"PAYLOAD_NOT_FOUND\", confidence=0.\n"
            "3. Extract the exact challenge nonce string found in the payload into detected_nonce (or \"NONE\" if missing). Check if detected_nonce exactly matches expected_nonce: set is_nonce_exact_match=true if exact match, otherwise false.\n"
            "4. Search for expected_claimant wallet address in extracted_body: set is_claimant_exact_match=true if present, otherwise false.\n"
            "5. Ownership is proven (verified=true) ONLY IF http_error=false, payload_found=true, is_nonce_exact_match=true, and is_claimant_exact_match=true. When verified=true, set failure_code=\"NONE\" and confidence=100.\n"
            "6. If verification fails, verified=false, confidence=0, and failure_code MUST be strictly one of:\n"
            "   - \"HTTP_ERROR\": HTTP request failed or error response.\n"
            "   - \"PAYLOAD_NOT_FOUND\": Response body empty or invalid.\n"
            "   - \"NONCE_MISMATCH\": Nonce missing from body or does not match expected_nonce.\n"
            "   - \"CLAIMANT_MISMATCH\": Claimant address missing or mismatched in body.\n\n"
            "Output JSON format:\n"
            "{\n"
            '  "http_error": true/false,\n'
            '  "payload_found": true/false,\n'
            '  "extracted_body": "<raw payload text or JSON string>",\n'
            '  "detected_nonce": "<exact nonce extracted from body, or NONE>",\n'
            '  "is_nonce_exact_match": true/false,\n'
            '  "is_claimant_exact_match": true/false,\n'
            '  "verified": true/false,\n'
            '  "failure_code": "<NONE, HTTP_ERROR, PAYLOAD_NOT_FOUND, NONCE_MISMATCH, or CLAIMANT_MISMATCH>",\n'
            '  "confidence": <integer 0 to 100>,\n'
            '  "summary": "<brief proof-of-control audit sentence>"\n'
            "}\n"
            "Respond ONLY with raw JSON."
        )

        criteria = (
            "ProofOfControl Strict Equivalence Rule:\n"
            "1. Strict Consensus Fields: http_error (bool), payload_found (bool), detected_nonce (str), "
            "is_nonce_exact_match (bool), is_claimant_exact_match (bool), verified (bool), and failure_code (str) "
            "MUST match 100% exactly across all validators.\n"
            "2. Fuzzy Part: confidence score (0 to 100) must match within a bounded tolerance of +-10 points within the same outcome tier. "
            "summary string may vary.\n"
            "Independently parse the live HTTP response and verify all evidence yourself. "
            "REJECT the leader's proposal if: "
            "(1) detected_nonce does not strictly match the exact nonce string present in the live HTTP body (or 'NONE' if absent), "
            "(2) is_nonce_exact_match is true when detected_nonce != expected_nonce, "
            "(3) is_claimant_exact_match is true when expected_claimant is not present in extracted_body, "
            "(4) verified is true when failure_code != 'NONE' or any mismatch exists, "
            "(5) failure_code is inconsistent with the HTTP body evidence in EITHER direction, "
            "(6) payload_found is false when valid challenge payload data is present, or "
            "(7) confidence score deviates by more than +-10 points. "
            "The output must be valid JSON with keys: http_error, payload_found, extracted_body, "
            "detected_nonce, is_nonce_exact_match, is_claimant_exact_match, verified, failure_code, confidence, and summary."
        )

        consensus_result = gl.eq_principle.prompt_non_comparative(
            get_input,
            task=task,
            criteria=criteria
        )

        # Clean thinking blocks and markdown wrappers
        raw_json = consensus_result.strip()
        if "</think>" in raw_json:
            raw_json = raw_json.split("</think>")[-1].strip()
        if raw_json.startswith("```"):
            lines = raw_json.split("\n")
            if len(lines) >= 3 and lines[0].startswith("```") and lines[-1].startswith("```"):
                raw_json = "\n".join(lines[1:-1]).strip()
            else:
                raw_json = raw_json.replace("```json", "").replace("```", "").strip()

        result = json.loads(raw_json)
        http_err = bool(result.get("http_error", False))
        payload_found = bool(result.get("payload_found", False))
        extracted_body = str(result.get("extracted_body", "")).strip()
        detected_nonce = str(result.get("detected_nonce", "")).strip()
        is_nonce_match = bool(result.get("is_nonce_exact_match", False))
        is_claimant_match = bool(result.get("is_claimant_exact_match", False))
        consensus_verified = bool(result.get("verified", False))
        fail_code = str(result.get("failure_code", "UNKNOWN_ERROR")).strip().upper()
        conf_score = int(result.get("confidence", 0))
        summary_val = str(result.get("summary", ""))

        # DETERMINISTIC PYTHON-SIDE INVARIANT VALIDATION (FAIL-CLOSED)
        # Eliminates bypass loopholes where failure_code != "NONE" or nonce is only echoed in detected_nonce.
        is_consistent_success = (
            (not http_err)
            and payload_found
            and consensus_verified
            and (fail_code == "NONE")
            and is_nonce_match
            and is_claimant_match
            and (detected_nonce.lower() == expected_nonce.lower())
            and (expected_nonce in extracted_body)
            and (expected_claimant.lower() in extracted_body.lower())
        )

        if is_consistent_success:
            # Control Verified Intact
            challenge.status = "VERIFIED"
            challenge.verified = True
            challenge.failure_code = "NONE"
            challenge.confidence_score = u256(conf_score)
            challenge.last_audit_summary = (
                f"PROOF OF CONTROL VERIFIED: Claimant '{expected_claimant}' proven in control of {t_type} '{t_id}'. "
                f"Cryptographic nonce '{expected_nonce}' validated in hosted payload. " + summary_val
            )
        else:
            # Control Verification Failed (Fail-Closed)
            challenge.status = "FAILED"
            challenge.verified = False
            challenge.confidence_score = u256(conf_score)

            if fail_code != "NONE" and fail_code != "UNKNOWN_ERROR":
                challenge.failure_code = fail_code
            elif http_err or not payload_found:
                challenge.failure_code = "PAYLOAD_NOT_FOUND" if not http_err else "HTTP_ERROR"
            elif (not is_nonce_match) or (detected_nonce.lower() != expected_nonce.lower()) or (expected_nonce not in extracted_body):
                challenge.failure_code = "NONCE_MISMATCH"
            elif (not is_claimant_match) or (expected_claimant.lower() not in extracted_body.lower()):
                challenge.failure_code = "CLAIMANT_MISMATCH"
            else:
                challenge.failure_code = "CONSENSUS_VERIFICATION_FAILED"

            challenge.last_audit_summary = (
                f"PROOF OF CONTROL FAILED [{challenge.failure_code}]: Verification invariants failed. " + summary_val
            )

        self.challenges[challenge_id] = challenge

    @gl.public.view
    def is_verified(self, challenge_id: str) -> bool:
        assert challenge_id in self.challenges, "[ERR_STATE_01] Challenge ID does not exist."
        return self.challenges[challenge_id].verified

    @gl.public.view
    def get_challenge(self, challenge_id: str) -> ChallengeRecord:
        assert challenge_id in self.challenges, "[ERR_STATE_01] Challenge ID does not exist."
        return self.challenges[challenge_id]

    @gl.public.view
    def get_total_challenges(self) -> u256:
        return self.next_challenge_id
