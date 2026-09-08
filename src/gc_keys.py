"""
GC Key Generation — Gottesman–Chuang Key Pairs and Copy Budget
================================================================

Implements:
  - Private key generation (classical L-bit strings, M positions × 2 bits)
  - Quantum public key generation (fingerprint states)
  - Public key copy budget tracking (resource accounting for no-cloning)

The copy budget is a finite quantum public-key copy budget modeled
through explicit logical resource accounting. In physical quantum hardware,
the no-cloning theorem prevents copying unknown states. In this software
simulation, logical resource accounting explicitly tracks and enforces copy limits.

Per GC (quant-ph/0105032, Section 4):
  - Alice chooses k_0^i, k_1^i ∈ {0,1}^L for i = 1..M
  - Public keys: {|f_{k_0^i}⟩, |f_{k_1^i}⟩}
  - Copy budget: T < L/n copies total in circulation
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum

import numpy as np
from qiskit.quantum_info import Statevector

from src.qowf import (
    DEFAULT_FINGERPRINT_QUBITS,
    DEFAULT_PRIVATE_KEY_BITS,
    encode,
    prepare_statevector,
)


# ---------------------------------------------------------------------------
#  Configuration
# ---------------------------------------------------------------------------

DEFAULT_POSITIONS = 32          # M — number of signature positions
DEFAULT_MAX_TOTAL_COPIES = 4    # T — max copies in circulation (2 per verifier × 2)


# ---------------------------------------------------------------------------
#  Data structures
# ---------------------------------------------------------------------------

class CopyStatus(Enum):
    """Status of a quantum public key copy."""
    AVAILABLE = "AVAILABLE"
    CONSUMED = "CONSUMED"       # Used in a SWAP test (destructive)
    DISTRIBUTED = "DISTRIBUTED" # Given to a verifier


@dataclass
class PublicKeyCopy:
    """
    A single logical copy of a quantum public key state.

    Represents one copy of |f_{k_b^i}⟩ held by a specific verifier.
    Each copy can be used ONCE for a SWAP test, after which it is consumed.

    This is a resource-accounting abstraction of the physical no-cloning
    constraint. In simulation, the statevector data is stored here.
    In reality, this would be a physical quantum state in quantum memory.
    """
    position: int           # Key position index i (0-based)
    bit: int                # Message bit b ∈ {0, 1}
    statevector: Statevector  # The quantum state |f_{k_b^i}⟩
    status: CopyStatus = CopyStatus.AVAILABLE
    owner: str = ""         # Verifier identity (e.g., "Bob", "Charlie")

    def consume(self) -> Statevector:
        """
        Consume this copy for verification (SWAP test).

        Returns the statevector and marks the copy as consumed.
        Raises RuntimeError if already consumed.
        """
        if self.status == CopyStatus.CONSUMED:
            raise RuntimeError(
                f"Public key copy (pos={self.position}, bit={self.bit}, "
                f"owner={self.owner}) already consumed. "
                "Finite quantum public-key copy budget modeled through explicit logical resource accounting: "
                "each copy can only be used once."
            )
        self.status = CopyStatus.CONSUMED
        return self.statevector


@dataclass
class CopyBudget:
    """
    Tracks the copy budget for quantum public keys.

    Per GC: T < L/n copies may be in circulation.
    This enforces the constraint programmatically via explicit logical resource accounting.
    """
    position: int
    bit: int
    max_copies: int
    distributed_copies: int = 0
    consumed_copies: int = 0

    @property
    def remaining_copies(self) -> int:
        return self.max_copies - self.distributed_copies

    def can_distribute(self) -> bool:
        return self.distributed_copies < self.max_copies

    def distribute(self) -> None:
        if not self.can_distribute():
            raise RuntimeError(
                f"Copy budget exhausted for pos={self.position}, bit={self.bit}. "
                f"Max={self.max_copies}, distributed={self.distributed_copies}. "
                "Finite quantum public-key copy budget modeled through explicit logical resource accounting."
            )
        self.distributed_copies += 1

    def record_consumption(self) -> None:
        self.consumed_copies += 1


@dataclass
class GCPrivateKey:
    """
    Alice's private key material for one signature position.

    Contains two L-bit classical strings:
      k_0: revealed when signing message bit 0
      k_1: revealed when signing message bit 1
    """
    position: int
    k0: bytes   # L-bit key for message bit 0
    k1: bytes   # L-bit key for message bit 1

    def get_key_for_bit(self, bit: int) -> bytes:
        """Return the private key corresponding to message bit b."""
        if bit == 0:
            return self.k0
        elif bit == 1:
            return self.k1
        else:
            raise ValueError(f"Message bit must be 0 or 1, got {bit}")


@dataclass
class GCKeyPair:
    """
    Complete GC key pair for a quantum digital signature instance.

    Contains M private key positions and the configuration parameters.
    Quantum public keys are generated on demand from private keys.
    """
    private_keys: list[GCPrivateKey]
    n_positions: int            # M
    fingerprint_qubits: int     # n
    private_key_length: int     # L (in bits)
    encoded_length: int         # N = 2^n
    max_total_copies: int       # T

    # Copy budget tracking for each (position, bit) pair
    copy_budgets: dict[tuple[int, int], CopyBudget] = field(default_factory=dict)

    def __post_init__(self):
        if not self.copy_budgets:
            for pk in self.private_keys:
                for b in (0, 1):
                    self.copy_budgets[(pk.position, b)] = CopyBudget(
                        position=pk.position,
                        bit=b,
                        max_copies=self.max_total_copies,
                    )

    def holevo_security_margin(self) -> int:
        """
        Compute L - T·n, the margin that must be >> 1 for security.
        Per GC: adversary learns at most T·n bits from T copies of n qubits.
        """
        return self.private_key_length - self.max_total_copies * self.fingerprint_qubits

    def generate_public_key_state(self, position: int, bit: int) -> Statevector:
        """
        Generate quantum public key |f_{k_b^i}⟩ from private key.

        This is the forward direction of the QOWF: easy to compute.
        """
        pk = self.private_keys[position]
        k = pk.get_key_for_bit(bit)
        codeword = encode(k, self.fingerprint_qubits)
        return prepare_statevector(codeword, self.fingerprint_qubits)

    def distribute_copy(self, position: int, bit: int, owner: str) -> PublicKeyCopy:
        """
        Create and distribute one copy of a quantum public key.

        Tracks copy budget and raises RuntimeError if budget exhausted.
        """
        budget = self.copy_budgets[(position, bit)]
        budget.distribute()  # Raises if budget exhausted

        sv = self.generate_public_key_state(position, bit)
        return PublicKeyCopy(
            position=position,
            bit=bit,
            statevector=sv,
            status=CopyStatus.DISTRIBUTED,
            owner=owner,
        )


# ---------------------------------------------------------------------------
#  Verifier's public key register
# ---------------------------------------------------------------------------

@dataclass
class VerifierKeyRegister:
    """
    A verifier's (Bob or Charlie) collection of quantum public key copies.

    Each verifier stores copies received during the distribution phase.
    Copies are consumed when used in SWAP test verification.
    """
    owner: str
    copies: dict[tuple[int, int], PublicKeyCopy] = field(default_factory=dict)

    def store(self, copy: PublicKeyCopy) -> None:
        """Store a distributed public key copy."""
        key = (copy.position, copy.bit)
        if key in self.copies:
            raise RuntimeError(
                f"Verifier {self.owner} already has a copy for "
                f"pos={copy.position}, bit={copy.bit}. "
                f"Duplicate distribution not allowed."
            )
        self.copies[key] = copy

    def get_copy(self, position: int, bit: int) -> PublicKeyCopy:
        """Retrieve a stored copy (does not consume it)."""
        key = (position, bit)
        if key not in self.copies:
            raise KeyError(
                f"Verifier {self.owner} has no public key copy for "
                f"pos={position}, bit={bit}."
            )
        return self.copies[key]

    def consume_copy(self, position: int, bit: int) -> Statevector:
        """
        Consume a stored copy for SWAP test verification.

        Returns the statevector and marks the copy as consumed.
        Raises RuntimeError if copy already consumed.
        """
        copy = self.get_copy(position, bit)
        return copy.consume()

    def has_available_copy(self, position: int, bit: int) -> bool:
        """Check if an unconsumed copy exists for the given position and bit."""
        key = (position, bit)
        if key not in self.copies:
            return False
        return self.copies[key].status in (CopyStatus.AVAILABLE, CopyStatus.DISTRIBUTED)


# ---------------------------------------------------------------------------
#  Key generation
# ---------------------------------------------------------------------------

class GCKeyGenerator:
    """Generates GC-style key pairs."""

    @staticmethod
    def generate(
        n_positions: int = DEFAULT_POSITIONS,
        fingerprint_qubits: int = DEFAULT_FINGERPRINT_QUBITS,
        private_key_bits: int = DEFAULT_PRIVATE_KEY_BITS,
        max_total_copies: int = DEFAULT_MAX_TOTAL_COPIES,
    ) -> GCKeyPair:
        """
        Generate a complete GC key pair.

        Args:
            n_positions: M — number of signature positions.
            fingerprint_qubits: n — qubits per fingerprint state.
            private_key_bits: L — bits per private key.
            max_total_copies: T — max copies in circulation.

        Returns:
            GCKeyPair with M private key positions.
        """
        key_bytes = private_key_bits // 8
        private_keys = []
        for i in range(n_positions):
            k0 = os.urandom(key_bytes)
            k1 = os.urandom(key_bytes)
            private_keys.append(GCPrivateKey(position=i, k0=k0, k1=k1))

        kp = GCKeyPair(
            private_keys=private_keys,
            n_positions=n_positions,
            fingerprint_qubits=fingerprint_qubits,
            private_key_length=private_key_bits,
            encoded_length=2 ** fingerprint_qubits,
            max_total_copies=max_total_copies,
        )

        # Verify Holevo security margin
        margin = kp.holevo_security_margin()
        if margin <= 0:
            raise ValueError(
                f"Holevo security margin L - T·n = {margin} <= 0. "
                f"Parameters are insecure: L={private_key_bits}, "
                f"T={max_total_copies}, n={fingerprint_qubits}."
            )

        return kp

    @staticmethod
    def distribute_to_verifier(
        key_pair: GCKeyPair,
        verifier_name: str,
    ) -> VerifierKeyRegister:
        """
        Distribute one copy of each quantum public key to a verifier.

        Creates a VerifierKeyRegister containing one copy of each
        |f_{k_b^i}⟩ for all positions i and bits b ∈ {0, 1}.

        Args:
            key_pair: The GC key pair (Alice's).
            verifier_name: Name of the verifier (e.g., "Bob").

        Returns:
            VerifierKeyRegister with all distributed copies.
        """
        register = VerifierKeyRegister(owner=verifier_name)
        for i in range(key_pair.n_positions):
            for b in (0, 1):
                copy = key_pair.distribute_copy(i, b, verifier_name)
                register.store(copy)
        return register
