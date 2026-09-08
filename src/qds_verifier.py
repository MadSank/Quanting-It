"""
GC QDS Verifier — Gottesman–Chuang Quantum Digital Signature Verification
==========================================================================

Implements the verification phase of the GC QDS protocol.

Per GC (quant-ph/0105032, Section 4):
  Each recipient checks each revealed key k_b^i by:
    1. Computing |f_{k_b^i}⟩ from the revealed classical key
    2. Performing a SWAP test against the stored quantum public key
    3. Counting failures (mismatches)

  Three-outcome acceptance:
    s_j ≤ c₁·M  →  1-ACC (valid and transferable)
    c₁·M < s_j < c₂·M  →  0-ACC (valid, not transferable)
    s_j ≥ c₂·M  →  REJ (invalid)

  where s_j is the number of failed SWAP tests for verifier j.

The SWAP test is DESTRUCTIVE: it consumes the stored quantum public
key copy. This is enforced via the copy budget model.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from qiskit.quantum_info import Statevector
from qiskit_aer import AerSimulator

from src.gc_keys import VerifierKeyRegister
from src.qds_signer import GCSignature, GCSigner
from src.qowf import encode, prepare_statevector
from src.swap_test import run_single_shot_swap_test, analytical_acceptance_probability


class VerificationOutcome(Enum):
    """GC three-outcome verification result."""
    ACC_1 = "1-ACC"     # Valid and transferable
    ACC_0 = "0-ACC"     # Valid, not necessarily transferable
    REJ = "REJ"         # Invalid / rejected


@dataclass
class GCVerificationResult:
    """
    Result of GC QDS signature verification.

    Contains detailed per-position results and the overall decision.
    """
    outcome: VerificationOutcome
    n_positions: int            # M
    n_failures: int             # s_j — number of failed SWAP tests
    n_passes: int               # number of passed SWAP tests
    mismatch_rate: float        # s_j / M
    acceptance_threshold: float # c₁
    rejection_threshold: float  # c₂

    # Per-position SWAP test results (True = pass, False = fail)
    position_results: list[bool]

    # Message consistency
    message_bits_match: bool    # Whether message encoding is consistent
    verifier_name: str = ""

    @property
    def is_valid(self) -> bool:
        return self.outcome != VerificationOutcome.REJ

    @property
    def n_mismatches(self) -> int:
        return self.n_failures

    @property
    def aggregate_mismatch_rate(self) -> float:
        return self.mismatch_rate

    @property
    def n_qubits(self) -> int:
        return self.n_positions

    @property
    def correction_bits_valid(self) -> bool:
        return True


class GCVerifier:
    """
    Implements GC-style quantum digital signature verification.

    A verifier (Bob or Charlie) uses their stored quantum public keys
    to verify a signature via SWAP tests.
    """

    def __init__(
        self,
        acceptance_threshold: float = 0.0,
        rejection_threshold: float = 0.15,
        mismatch_threshold: float = None,
        key_register: VerifierKeyRegister = None,
    ):
        """
        Initialize verifier with GC thresholds.

        Args:
            acceptance_threshold: c₁ — max mismatch rate for 1-ACC.
                In noiseless simulation, c₁ = 0.0 (honest signatures
                always achieve zero mismatches).
            rejection_threshold: c₂ — min mismatch rate for REJ.
                Must satisfy c₂ > c₁. The gap c₂ - c₁ prevents
                Alice from cheating (GC Section 7).
            mismatch_threshold: Legacy parameter mapping to c₁.
        """
        if mismatch_threshold is not None:
            acceptance_threshold = mismatch_threshold
            if rejection_threshold <= acceptance_threshold:
                rejection_threshold = acceptance_threshold + 0.15

        if rejection_threshold <= acceptance_threshold:
            raise ValueError(
                f"Rejection threshold c₂={rejection_threshold} must be > "
                f"acceptance threshold c₁={acceptance_threshold}"
            )
        self.c1 = acceptance_threshold
        self.c2 = rejection_threshold
        self.key_register = key_register
        self.sim = AerSimulator()

    def verify(
        self,
        signature: GCSignature,
        key_register: VerifierKeyRegister = None,
        message: bytes = None,
        *args,
        **kwargs,
    ) -> GCVerificationResult:
        """
        Verify a GC QDS signature.

        For each position i:
          1. Extract revealed key k from signature
          2. Compute |f_k⟩ from the revealed key (forward direction of QOWF)
          3. Consume stored quantum public key copy for position i, bit b_i
          4. Run SWAP test between computed |f_k⟩ and stored copy
          5. Record pass/fail

        Then apply threshold decision.
        """
        # Handle flexible parameter ordering for compatibility
        if key_register is not None and not isinstance(key_register, VerifierKeyRegister):
            if message is None:
                message = key_register
            key_register = self.key_register

        if key_register is None:
            key_register = self.key_register

        if message is None:
            message = getattr(signature, 'message', b"")

        if isinstance(message, str):
            message = message.encode("utf-8")

        verifier_owner = key_register.owner if key_register else "Verifier"

        if key_register is None:
            # No register provided: reject due to missing public keys
            return GCVerificationResult(
                outcome=VerificationOutcome.REJ,
                n_positions=signature.n_positions,
                n_failures=signature.n_positions,
                n_passes=0,
                mismatch_rate=1.0,
                acceptance_threshold=self.c1,
                rejection_threshold=self.c2,
                position_results=[False] * signature.n_positions,
                message_bits_match=False,
                verifier_name="Unregistered",
            )

        # Step 0: Re-encode the message to verify consistency
        expected_bits = GCSigner.encode_message(message, signature.n_positions)
        message_bits_match = (expected_bits == signature.message_bits)

        # If message encoding doesn't match, reject immediately
        if not message_bits_match:
            return GCVerificationResult(
                outcome=VerificationOutcome.REJ,
                n_positions=signature.n_positions,
                n_failures=signature.n_positions,
                n_passes=0,
                mismatch_rate=1.0,
                acceptance_threshold=self.c1,
                rejection_threshold=self.c2,
                position_results=[False] * signature.n_positions,
                message_bits_match=False,
                verifier_name=key_register.owner,
            )

        position_results = []
        n_failures = 0

        for i in range(signature.n_positions):
            bit = signature.message_bits[i]
            revealed_key = signature.revealed_keys[i]

            # Step 1: Compute |f_k⟩ from revealed key
            codeword = encode(revealed_key, signature.fingerprint_qubits)
            fresh_state = prepare_statevector(codeword, signature.fingerprint_qubits)

            # Step 2: Consume stored quantum public key copy
            try:
                stored_state = key_register.consume_copy(i, bit)
            except (KeyError, RuntimeError):
                # No available copy → fail this position
                position_results.append(False)
                n_failures += 1
                continue

            # Step 3: SWAP test
            passed = run_single_shot_swap_test(
                fresh_state, stored_state,
                signature.fingerprint_qubits,
                sim=self.sim,
            )
            position_results.append(passed)
            if not passed:
                n_failures += 1

        # Step 4: Threshold decision
        mismatch_rate = n_failures / signature.n_positions if signature.n_positions > 0 else 0.0

        if mismatch_rate <= self.c1:
            outcome = VerificationOutcome.ACC_1
        elif mismatch_rate < self.c2:
            outcome = VerificationOutcome.ACC_0
        else:
            outcome = VerificationOutcome.REJ

        return GCVerificationResult(
            outcome=outcome,
            n_positions=signature.n_positions,
            n_failures=n_failures,
            n_passes=signature.n_positions - n_failures,
            mismatch_rate=mismatch_rate,
            acceptance_threshold=self.c1,
            rejection_threshold=self.c2,
            position_results=position_results,
            message_bits_match=message_bits_match,
            verifier_name=key_register.owner,
        )


QDSVerifier = GCVerifier
