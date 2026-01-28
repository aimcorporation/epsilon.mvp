"""
A.I.M. Zero-Trust Command Interceptor
Production-grade policy-enforced command execution with signing
© 2026 — All rights reserved.
"""

import logging
import shlex
import subprocess
import sys
import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, List, Any

from command_normalizer import CommandNormalizer
from models.command_sequence_model import CommandSequenceModel
from signing.hardware_identity import HardwareIdentity

logger = logging.getLogger(__name__)

class ZeroTrustCLI:
    """
    Zero-trust command execution wrapper with risk scoring, policy checks, JIT elevation, audit logging, constrained run, and hardware signing (testing mode).
    """
    def __init__(self, user: str, device: str, session_token: str):
        self.user = user
        self.device = device
        self.session_token = session_token
        self.policy_cache: Dict[str, Any] = {}
        self.normalizer = CommandNormalizer()
        self.anomaly_model = CommandSequenceModel(window_size=10)
        self.command_history: List[str] = []
        self.signer = HardwareIdentity()  # Hardware signing (testing mode)

    def execute(self, raw_command: str) -> Dict[str, Any]:
        """
        Execute a command under zero-trust rules with signing.
        Returns result or raises PermissionError on policy block.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        audit_id = self._generate_audit_id(raw_command, timestamp)

        # Step 1: Normalize + threat scan
        norm_result = self.normalizer.normalize_and_scan(raw_command)
        logger.info(f"Normalized command: {norm_result['normalized']}")
        if norm_result["threats"]:
            self._log_blocked(audit_id, raw_command, "Threat detected in normalization")
            raise PermissionError(f"Blocked: {', '.join(norm_result['threats'])}")
        if norm_result["obfuscation_detected"]:
            self._log_blocked(audit_id, raw_command, "Obfuscation detected")
            raise PermissionError("Blocked: Obfuscation/evasion detected")

        # Step 2: Anomaly detection
        self.command_history.append(raw_command)
        if len(self.command_history) >= self.anomaly_model.window_size:
            anomaly_result = self.anomaly_model.evaluate(self.command_history[-self.anomaly_model.window_size:])
            logger.info(f"Anomaly score: {anomaly_result['anomaly_score']} | Is anomaly: {anomaly_result['is_anomaly']}")
            if anomaly_result["anomaly_score"] < -0.05:
                self._log_blocked(audit_id, raw_command, "Behavioral anomaly detected")
                raise PermissionError("Blocked: Behavioral anomaly detected (score below threshold)")

        # Step 3: Risk scoring
        risk_score = self._evaluate_risk(norm_result["normalized"])
        logger.info(f"Risk score for '{raw_command[:50]}...': {risk_score}")

        # Step 4: Policy evaluation
        policy_result = self._evaluate_policy(norm_result["normalized"], risk_score)
        if not policy_result["allowed"]:
            self._log_blocked(audit_id, raw_command, policy_result["reason"])
            raise PermissionError(f"Blocked by policy: {policy_result['reason']}")

        # Step 5: JIT elevation (stub)
        if policy_result["needs_jit"]:
            logger.warning("JIT elevation required - stubbed")

        # Step 6: Sign command (non-repudiation)
        signed = self.signer.sign_command(raw_command)
        logger.info(f"Signed command: {signed['status']}")

        # Step 7: Audit log before execution
        self._log_execution(audit_id, raw_command, timestamp)

        # Step 8: Constrained execution
        try:
            result = self._run_constrained(raw_command)
            self._log_success(audit_id, result)
            return {
                "status": "success",
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "signed": signed  # Include signed payload for audit
            }
        except Exception as e:
            self._log_failure(audit_id, str(e))
            raise RuntimeError(f"Execution failed: {str(e)}")

    def _generate_audit_id(self, command: str, timestamp: str) -> str:
        """Generate unique audit ID from command + timestamp + session."""
        hash_input = f"{command}|{timestamp}|{self.session_token}"
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]

    def _evaluate_risk(self, command: str) -> int:
        """Simple risk scoring (expand with ML or threat intel later)."""
        score = 0
        if "sudo" in command or "su" in command:
            score += 40
        if any(p in command for p in ["/etc/shadow", "/proc", "/dev/mem"]):
            score += 30
        if "rm -rf" in command:
            score += 50
        return min(score, 100)

    def _evaluate_policy(self, command: str, risk_score: int) -> Dict[str, Any]:
        """Dynamic policy check (stub - integrate real policy engine later)."""
        if risk_score > 70:
            return {"allowed": False, "reason": "High risk score", "needs_jit": False}
        if "rm -rf /" in command:
            return {"allowed": False, "reason": "Destructive command blocked", "needs_jit": False}
        return {"allowed": True, "reason": "Allowed", "needs_jit": False}

    def _log_blocked(self, audit_id: str, command: str, reason: str):
        """Log blocked command for audit."""
        logger.warning(f"[BLOCKED] Audit ID: {audit_id} | Command: {command[:100]}... | Reason: {reason}")

    def _log_execution(self, audit_id: str, command: str, timestamp: str):
        """Log pre-execution audit entry."""
        logger.info(f"[EXEC] Audit ID: {audit_id} | User: {self.user} | Command: {command[:100]}... | Time: {timestamp}")

    def _log_success(self, audit_id: str, result: subprocess.CompletedProcess):
        """Log successful execution."""
        logger.info(f"[SUCCESS] Audit ID: {audit_id} | Return code: {result.returncode}")

    def _log_failure(self, audit_id: str, error: str):
        """Log execution failure."""
        logger.error(f"[FAILURE] Audit ID: {audit_id} | Error: {error}")

    def _run_constrained(self, raw_command: str) -> subprocess.CompletedProcess:
        """Execute command in constrained environment (stub - use bubblewrap/nsjail later)."""
        # TODO: Replace with real constrained runner (bwrap, nsjail, landlock, etc.)
        cmd_parts = shlex.split(raw_command)
        return subprocess.run(
            cmd_parts,
            capture_output=True,
            text=True,
            timeout=30
        )


if __name__ == "__main__":
    cli = ZeroTrustCLI(user="jeb", device="laptop", session_token="abc123")
    try:
        result = cli.execute("ls -la")
        print("Execution result:", result)
    except PermissionError as e:
        print("Blocked:", str(e))
    except Exception as e:
        print("Execution error:", str(e))