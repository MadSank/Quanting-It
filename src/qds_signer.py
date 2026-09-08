"""
GC QDS Signer — Gottesman–Chuang Quantum Digital Signature Signing
===================================================================

Implements the signing phase of the GC QDS protocol.

Per GC (quant-ph/0105032, Section 4):
  To sign a single-bit message b, Alice sends:
    (b, k_b^1, k_b^2, ..., k_b^M)

  That is, for each position i, Alice reveals the classical private key
  corresponding to message bit b_i.

For multi-bit messages, we encode the message into M bits:
  - If len(message) <= M bits: direct binary encoding
  - Otherwise: SHA-256 hash → M-bit digest (configurable)

The signature is the set of revealed classical private keys plus
the message encoding and session metadata.

ML-DSA is used as an AUXILIARY classical authentication layer for
the transcript — it is NOT the QDS itself.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from src.gc_keys import GCKeyPair


@dataclass
class GCSignature:
    """
    A Gottesman–Chuang quantum digital signature.

    Contains the revealed private keys for each signature position,
    corresponding to the encoded message bits.
    """
    # Message
    message: bytes                      # Original message
    message_bits: list[int]             # M-bit encoding of message
    n_positions: int                    # M

    # Revealed keys: for position i, the key k_{message_bits[i]}^i
    revealed_keys: list[bytes]          # M keys, each L/8 bytes

    # Protocol parameters
    fingerprint_qubits: int             # n
    private_key_bits: int               # L

    # Session binding
    session_id: str = ""
    sequence_number: int = 0

    # Auxiliary classical authentication (ML-DSA)
    classical_auth_tag: str = ""
    classical_pub_key: str = ""

    @property
    def n_qubits(self) -> int:
        return self.n_positions

    @property
    def correction_bits(self) -> str:
        return b"".join(self.revealed_keys).hex()

    @property
    def correction_auth_tag(self) -> str:
        return self.classical_auth_tag

    @correction_auth_tag.setter
    def correction_auth_tag(self, val: str) -> None:
        self.classical_auth_tag = val

    @property
    def teleported_states(self) -> list:
        return []


class GCSigner:
    """
    Implements GC-style quantum digital signature signing.

    Alice uses this to sign a message by revealing the appropriate
    private keys from her GC key pair.
    """

    @staticmethod
    def encode_message(message: bytes, n_positions: int) -> list[int]:
        """
        Encode a message into M bits for signing.

        For the prototype, we hash the message with SHA-256 and take
        the first M bits. This provides domain separation and fixed-length
        encoding.

        # NOTE: SHA-256 is used here for MESSAGE HASHING / DOMAIN BINDING.
        # Key expansion in qowf.encode() is a deterministic pseudorandom
        # codeword/fingerprint encoding for the prototype, not a formal ECC.

        Args:
            message: Arbitrary message bytes.
            n_positions: M — number of signature positions.

        Returns:
            List of M bits (0 or 1).
        """
        h = hashlib.sha256(message).digest()
        # Extract M bits from the hash
        bits = []
        for byte_val in h:
            for bit_pos in range(8):
                if len(bits) < n_positions:
                    bits.append((byte_val >> bit_pos) & 1)
        # If M > 256 (SHA-256 output), extend with another hash
        if len(bits) < n_positions:
            h2 = hashlib.sha256(h + b"extend").digest()
            for byte_val in h2:
                for bit_pos in range(8):
                    if len(bits) < n_positions:
                        bits.append((byte_val >> bit_pos) & 1)
        return bits[:n_positions]

    @staticmethod
    def sign(
        message: bytes,
        key_pair: GCKeyPair,
        session_id: str = "",
        sequence_number: int = 0,
    ) -> GCSignature:
        """
        Sign a message using the GC QDS protocol.

        For each position i, reveals k_{b_i}^i where b_i is the i-th
        bit of the encoded message.

        IMPORTANT: Bob does NOT possess Alice's private keys.
        Bob does NOT derive the expected signature from a shared secret.
        The signature IS the revealed private keys themselves.

        Args:
            message: The message to sign (arbitrary bytes).
            key_pair: Alice's GC key pair.
            session_id: Session identifier for binding.
            sequence_number: Sequence number for replay protection.

        Returns:
            GCSignature containing the revealed private keys.
        """
        message_bits = GCSigner.encode_message(message, key_pair.n_positions)

        revealed_keys = []
        for i in range(key_pair.n_positions):
            bit = message_bits[i]
            pk = key_pair.private_keys[i]
            revealed_keys.append(pk.get_key_for_bit(bit))

        return GCSignature(
            message=message,
            message_bits=message_bits,
            n_positions=key_pair.n_positions,
            revealed_keys=revealed_keys,
            fingerprint_qubits=key_pair.fingerprint_qubits,
            private_key_bits=key_pair.private_key_length,
            session_id=session_id,
            sequence_number=sequence_number,
        )


QDSSigner = GCSigner
QDSSignature = GCSignature
