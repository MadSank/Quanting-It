"""
[E91-BASED QUANTUM PUBLIC-KEY DISTRIBUTION]

First-class pipeline stage implementing Bell-state entanglement distribution
between Alice and Bob. Uses E91-style correlation verification to detect
eavesdropping during the key distribution phase itself.

This replaces the old seeded-PRNG "correlated bitstring" with actual
Bell pair circuit simulation on qiskit_aer.
"""

import hashlib
import random
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator


@dataclass
class QuantumKeyMaterial:
    """
    Output of the QPKD phase. Contains the shared quantum resources
    and session authentication context derived from entanglement.
    """
    session_id: str
    n_signature_pairs: int
    n_monitor_pairs: int
    # Simulated Bell pair statevectors allocated for signing
    signature_statevectors: List[Any] = field(default_factory=list)
    # Correlated bits from E91 check measurements
    alice_check_bits: List[int] = field(default_factory=list)
    bob_check_bits: List[int] = field(default_factory=list)
    alice_check_bases: List[str] = field(default_factory=list)
    bob_check_bases: List[str] = field(default_factory=list)
    # E91 distribution statistics
    distribution_error_rate: float = 0.0
    distribution_secure: bool = True
    # Derived session authentication context
    session_auth_context: str = ""


class QPKDSession:
    """
    E91-style Quantum Public-Key Distribution.

    Distributes Bell pairs between Alice and Bob. A subset of pairs are
    used for E91-style correlation verification (detecting Eve during
    distribution). The remaining pairs are allocated for QDS signing.
    """

    def __init__(self, session_id: str, error_threshold: float = 0.15):
        self.session_id = session_id
        self.error_threshold = error_threshold
        self.sim = AerSimulator()
        self.key_material: Optional[QuantumKeyMaterial] = None

    def distribute_keys(self, n_signature_pairs: int = 64,
                        n_monitor_pairs: int = 50) -> QuantumKeyMaterial:
        """
        Execute the full E91-based key distribution phase.

        1. Generate Bell pairs for both signing and monitoring.
        2. Run E91 correlation check on monitor pairs.
        3. If channel is clean, allocate signature pairs.
        4. Derive session auth context from correlated measurements.

        Args:
            n_signature_pairs: Number of Bell pairs for QDS signing (64 or 128)
            n_monitor_pairs: Number of Bell pairs for E91 channel check

        Returns:
            QuantumKeyMaterial with all shared resources
        """
        # Phase 1: E91 channel verification using monitor pairs
        alice_check_bits = []
        bob_check_bits = []
        alice_check_bases = []
        bob_check_bases = []
        errors = 0
        matches = 0

        for _ in range(n_monitor_pairs):
            # Create Bell pair |Φ+⟩ = (|00⟩ + |11⟩)/√2
            qc = QuantumCircuit(2, 2)
            qc.h(0)
            qc.cx(0, 1)

            # Alice and Bob independently choose random bases
            a_basis = random.choice(['Z', 'X'])
            b_basis = random.choice(['Z', 'X'])

            # Apply basis rotations before measurement
            if a_basis == 'X':
                qc.h(0)
            if b_basis == 'X':
                qc.h(1)

            qc.measure(0, 0)
            qc.measure(1, 1)

            result = self.sim.run(qc, shots=1).result()
            counts = result.get_counts()
            outcome = list(counts.keys())[0]

            # Qiskit bit ordering: outcome[0] = qubit 1 (Bob), outcome[1] = qubit 0 (Alice)
            alice_bit = int(outcome[1])
            bob_bit = int(outcome[0])

            alice_check_bits.append(alice_bit)
            bob_check_bits.append(bob_bit)
            alice_check_bases.append(a_basis)
            bob_check_bases.append(b_basis)

            # Check correlation only when bases match
            if a_basis == b_basis:
                matches += 1
                if alice_bit != bob_bit:
                    errors += 1

        # Compute distribution error rate
        error_rate = errors / matches if matches > 0 else 0.0
        distribution_secure = error_rate <= self.error_threshold

        # Phase 2: Generate signature Bell pairs (statevectors for simulation)
        signature_statevectors = []
        if distribution_secure:
            for _ in range(n_signature_pairs):
                qc = QuantumCircuit(2)
                qc.h(0)
                qc.cx(0, 1)
                qc.save_statevector()
                result = self.sim.run(qc).result()
                sv = result.get_statevector()
                signature_statevectors.append(sv)

        # Phase 3: Derive session authentication context
        # Use correlated bits from matching-basis measurements as seed material
        matching_bits = []
        for i in range(len(alice_check_bits)):
            if alice_check_bases[i] == bob_check_bases[i]:
                matching_bits.append(str(alice_check_bits[i]))

        correlated_string = "".join(matching_bits)
        context_input = f"{correlated_string}{self.session_id}"
        session_auth_context = hashlib.sha256(
            context_input.encode('utf-8')
        ).hexdigest()

        self.key_material = QuantumKeyMaterial(
            session_id=self.session_id,
            n_signature_pairs=n_signature_pairs,
            n_monitor_pairs=n_monitor_pairs,
            signature_statevectors=signature_statevectors,
            alice_check_bits=alice_check_bits,
            bob_check_bits=bob_check_bits,
            alice_check_bases=alice_check_bases,
            bob_check_bases=bob_check_bases,
            distribution_error_rate=error_rate,
            distribution_secure=distribution_secure,
            session_auth_context=session_auth_context,
        )
        return self.key_material

    def get_session_auth_context(self) -> str:
        """Returns the derived session authentication context."""
        if self.key_material is None:
            raise RuntimeError("QPKD distribution has not been executed yet.")
        return self.key_material.session_auth_context
