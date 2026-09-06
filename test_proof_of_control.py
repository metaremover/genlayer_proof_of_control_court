import sys
import os
import json
import unittest
from types import ModuleType

# Setup GenLayer VM Mocks for standalone testing
mock_gl_module = ModuleType('genlayer')
mock_gl_module.allow_storage = lambda cls: cls

class u256(int):
    pass

class TreeMap(dict):
    def __class_getitem__(cls, item):
        return cls

class Contract:
    def __new__(cls, *args, **kwargs):
        instance = super().__new__(cls)
        for name, typ in getattr(cls, '__annotations__', {}).items():
            origin = getattr(typ, '__origin__', typ)
            if origin is TreeMap or typ is TreeMap:
                setattr(instance, name, TreeMap())
        return instance

class Message:
    sender_address = "0x5c48c6f77617fc05761433cc4019a79b47d1ec7d"

class Web:
    @staticmethod
    def render(url, mode="text"):
        return ""

class Nondet:
    web = Web()

class EqPrinciple:
    consensus_return_value = "{}"

    def prompt_non_comparative(self, get_input_fn, task="", criteria=""):
        return getattr(self, "consensus_return_value", self.__class__.consensus_return_value)

class GL:
    Contract = Contract
    message = Message()
    nondet = Nondet()
    eq_principle = EqPrinciple()
    public = ModuleType('public')
    public.write = lambda fn: fn
    public.view = lambda fn: fn

mock_gl_module.u256 = u256
mock_gl_module.TreeMap = TreeMap
mock_gl_module.gl = GL()
sys.modules['genlayer'] = mock_gl_module

# Now import the actual contract code
import proof_of_control
from proof_of_control import ProofOfControlCourt, ChallengeRecord


class TestProofOfControlCourt(unittest.TestCase):
    def setUp(self):
        self.operator = "0x5c48c6f77617fc05761433cc4019a79b47d1ec7d"
        mock_gl_module.gl.message.sender_address = self.operator
        self.court = ProofOfControlCourt(operator=self.operator)

    def test_tc01_valid_proof_of_control_happy_path(self):
        """TC-01: Valid Proof of Control (Happy Path) -> VERIFIED"""
        res_str = self.court.request_challenge("DOMAIN", "tumhi4.github.io")
        res = json.loads(res_str)
        c_id = res["challenge_id"]
        nonce = res["required_nonce"]

        # Mock honest validator consensus output
        mock_output = {
            "http_error": False,
            "payload_found": True,
            "extracted_body": json.dumps({
                "genlayer_proof_of_control": {
                    "claimant_address": self.operator,
                    "target_id": "tumhi4.github.io",
                    "challenge_id": c_id,
                    "nonce": nonce
                }
            }),
            "detected_nonce": nonce,
            "is_nonce_exact_match": True,
            "is_claimant_exact_match": True,
            "verified": True,
            "failure_code": "NONE",
            "confidence": 100,
            "summary": "Claimant confirmed control of domain tumhi4.github.io."
        }
        mock_gl_module.gl.eq_principle.consensus_return_value = json.dumps(mock_output)

        self.court.verify_control(c_id)
        challenge = self.court.get_challenge(c_id)

        self.assertTrue(challenge.verified)
        self.assertEqual(challenge.status, "VERIFIED")
        self.assertEqual(challenge.failure_code, "NONE")
        self.assertEqual(challenge.confidence_score, 100)
        self.assertTrue(self.court.is_verified(c_id))
        self.assertIn("PROOF OF CONTROL VERIFIED", challenge.last_audit_summary)

    def test_tc02_steward_exploit_regression_nonce_mismatch_with_echoed_detected_nonce(self):
        """TC-02: Steward Exploit Scenario (Regression Test)
        Vulnerability: Validator reports NONCE_MISMATCH, but detected_nonce contains expected_nonce.
        The vulnerable code did: (expected_nonce in extracted_body) or (expected_nonce in detected_nonce).
        The fixed code requires strict consensus and all invariants: MUST FAIL-CLOSED.
        """
        res_str = self.court.request_challenge("DOMAIN", "exploit-target.org")
        res = json.loads(res_str)
        c_id = res["challenge_id"]
        expected_nonce = res["required_nonce"]

        # Attacker hosted a file without expected_nonce, but validator echoes expected_nonce in detected_nonce
        mock_output = {
            "http_error": False,
            "payload_found": True,
            "extracted_body": json.dumps({
                "genlayer_proof_of_control": {
                    "claimant_address": self.operator,
                    "target_id": "exploit-target.org",
                    "challenge_id": c_id,
                    "nonce": "ATTACKER_BOGUS_NONCE_9999999"
                }
            }),
            "detected_nonce": expected_nonce,  # Echoed / unchecked in vulnerable version!
            "is_nonce_exact_match": False,
            "is_claimant_exact_match": True,
            "verified": False,
            "failure_code": "NONCE_MISMATCH",
            "confidence": 0,
            "summary": "Nonce mismatch detected: hosted nonce does not match challenge."
        }
        mock_gl_module.gl.eq_principle.consensus_return_value = json.dumps(mock_output)

        self.court.verify_control(c_id)
        challenge = self.court.get_challenge(c_id)

        # Invariant check: MUST NOT BE VERIFIED!
        self.assertFalse(challenge.verified)
        self.assertEqual(challenge.status, "FAILED")
        self.assertEqual(challenge.failure_code, "NONCE_MISMATCH")
        self.assertFalse(self.court.is_verified(c_id))
        self.assertIn("PROOF OF CONTROL FAILED [NONCE_MISMATCH]", challenge.last_audit_summary)

    def test_tc03_http_fetch_error_or_404(self):
        """TC-03: HTTP 404 / Network Fetch Error -> FAILED (HTTP_ERROR)"""
        res_str = self.court.request_challenge("DOMAIN", "nonexistent-site-404.com")
        res = json.loads(res_str)
        c_id = res["challenge_id"]

        mock_output = {
            "http_error": True,
            "payload_found": False,
            "extracted_body": "HTTP 404 Not Found",
            "detected_nonce": "NONE",
            "is_nonce_exact_match": False,
            "is_claimant_exact_match": False,
            "verified": False,
            "failure_code": "HTTP_ERROR",
            "confidence": 0,
            "summary": "HTTP 404: Endpoint unreachable."
        }
        mock_gl_module.gl.eq_principle.consensus_return_value = json.dumps(mock_output)

        self.court.verify_control(c_id)
        challenge = self.court.get_challenge(c_id)

        self.assertFalse(challenge.verified)
        self.assertEqual(challenge.status, "FAILED")
        self.assertEqual(challenge.failure_code, "HTTP_ERROR")

    def test_tc04_claimant_address_mismatch(self):
        """TC-04: Claimant Address Mismatch -> FAILED (CLAIMANT_MISMATCH)"""
        res_str = self.court.request_challenge("DOMAIN", "other-owner.com")
        res = json.loads(res_str)
        c_id = res["challenge_id"]
        nonce = res["required_nonce"]

        # Body contains correct nonce but different claimant address
        mock_output = {
            "http_error": False,
            "payload_found": True,
            "extracted_body": json.dumps({
                "claimant_address": "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "nonce": nonce
            }),
            "detected_nonce": nonce,
            "is_nonce_exact_match": True,
            "is_claimant_exact_match": False,
            "verified": False,
            "failure_code": "CLAIMANT_MISMATCH",
            "confidence": 0,
            "summary": "Claimant wallet mismatch."
        }
        mock_gl_module.gl.eq_principle.consensus_return_value = json.dumps(mock_output)

        self.court.verify_control(c_id)
        challenge = self.court.get_challenge(c_id)

        self.assertFalse(challenge.verified)
        self.assertEqual(challenge.status, "FAILED")
        self.assertEqual(challenge.failure_code, "CLAIMANT_MISMATCH")

    def test_tc05_malicious_consensus_desync_missing_body_nonce(self):
        """TC-05: Malicious Consensus Desync / Injection Attempt
        Validator consensus proposes verified=True, but extracted_body does not contain expected_nonce.
        Deterministic Python validation must catch this and fail closed.
        """
        res_str = self.court.request_challenge("DOMAIN", "injected-response.com")
        res = json.loads(res_str)
        c_id = res["challenge_id"]
        expected_nonce = res["required_nonce"]

        mock_output = {
            "http_error": False,
            "payload_found": True,
            "extracted_body": f"claimant={self.operator}; nonce=COMPLETELY_DIFFERENT_VALUE",
            "detected_nonce": expected_nonce,
            "is_nonce_exact_match": True,
            "is_claimant_exact_match": True,
            "verified": True,
            "failure_code": "NONE",
            "confidence": 100,
            "summary": "Bogus approval by malicious leader."
        }
        mock_gl_module.gl.eq_principle.consensus_return_value = json.dumps(mock_output)

        self.court.verify_control(c_id)
        challenge = self.court.get_challenge(c_id)

        # Python invariant (expected_nonce in extracted_body) fails!
        self.assertFalse(challenge.verified)
        self.assertEqual(challenge.status, "FAILED")
        self.assertEqual(challenge.failure_code, "NONCE_MISMATCH")

    def test_tc06_empty_or_malformed_payload(self):
        """TC-06: Empty or Malformed Payload -> FAILED (PAYLOAD_NOT_FOUND)"""
        res_str = self.court.request_challenge("GITHUB_REPO", "octocat/Hello-World")
        res = json.loads(res_str)
        c_id = res["challenge_id"]

        mock_output = {
            "http_error": False,
            "payload_found": False,
            "extracted_body": "",
            "detected_nonce": "NONE",
            "is_nonce_exact_match": False,
            "is_claimant_exact_match": False,
            "verified": False,
            "failure_code": "PAYLOAD_NOT_FOUND",
            "confidence": 0,
            "summary": "Payload not found."
        }
        mock_gl_module.gl.eq_principle.consensus_return_value = json.dumps(mock_output)

        self.court.verify_control(c_id)
        challenge = self.court.get_challenge(c_id)

        self.assertFalse(challenge.verified)
        self.assertEqual(challenge.status, "FAILED")
        self.assertEqual(challenge.failure_code, "PAYLOAD_NOT_FOUND")

    def test_tc07_access_control_unauthorized_caller(self):
        """TC-07: Unauthorized caller cannot verify challenge -> ERR_AUTH_01"""
        res_str = self.court.request_challenge("DOMAIN", "protected-site.com")
        res = json.loads(res_str)
        c_id = res["challenge_id"]

        # Switch caller to unauthorized address
        mock_gl_module.gl.message.sender_address = "0x9999999999999999999999999999999999999999"

        with self.assertRaises(AssertionError) as ctx:
            self.court.verify_control(c_id)
        self.assertIn("[ERR_AUTH_01]", str(ctx.exception))

    def test_tc08_replay_prevention_already_finalized(self):
        """TC-08: Re-verifying a finalized challenge is rejected -> ERR_STATE_02"""
        res_str = self.court.request_challenge("DOMAIN", "replay-site.com")
        res = json.loads(res_str)
        c_id = res["challenge_id"]
        nonce = res["required_nonce"]

        mock_output = {
            "http_error": False,
            "payload_found": True,
            "extracted_body": f"{self.operator} {nonce}",
            "detected_nonce": nonce,
            "is_nonce_exact_match": True,
            "is_claimant_exact_match": True,
            "verified": True,
            "failure_code": "NONE",
            "confidence": 100,
            "summary": "Verified"
        }
        mock_gl_module.gl.eq_principle.consensus_return_value = json.dumps(mock_output)
        self.court.verify_control(c_id)

        # Attempt to verify again
        with self.assertRaises(AssertionError) as ctx:
            self.court.verify_control(c_id)
        self.assertIn("[ERR_STATE_02]", str(ctx.exception))

    def test_tc09_input_sanitization_and_validation(self):
        """TC-09: Target ID Sanitization and Type Validation"""
        # Protocol stripping: https://example.com/ should normalize to example.com
        res_str = self.court.request_challenge("DOMAIN", "https://example.com/")
        res = json.loads(res_str)
        self.assertEqual(res["target_id"], "example.com")
        self.assertEqual(res["host_url"], "https://example.com/genlayer-control.json")

        # Invalid target type
        with self.assertRaises(AssertionError) as ctx:
            self.court.request_challenge("TWITTER", "@test")
        self.assertIn("[ERR_TYPE_01]", str(ctx.exception))

        # Invalid domain with path slashes
        with self.assertRaises(AssertionError) as ctx:
            self.court.request_challenge("DOMAIN", "example.com/subpath")
        self.assertIn("[ERR_VAL_01]", str(ctx.exception))

        # Invalid GITHUB_REPO format (needs owner/repo)
        with self.assertRaises(AssertionError) as ctx:
            self.court.request_challenge("GITHUB_REPO", "onlyrepo")
        self.assertIn("[ERR_VAL_02]", str(ctx.exception))


if __name__ == '__main__':
    unittest.main(verbosity=2)
