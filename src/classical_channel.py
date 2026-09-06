"""
[CLASSICAL CONTROL CHANNEL - PQC LAYER]

This module provides ML-DSA (FIPS 204) authentication for the classical
control channel ONLY. It has two responsibilities:

1. Session metadata authentication: Signs session ID, challenge, and
   sequence numbers during negotiation.
2. Correction bit binding: Signs the concatenated crz/crx teleportation
   correction bits. This prevents a classical MitM from flipping correction
   bits to cause a Denial-of-Service attack.

IMPORTANT: This PQC layer is computationally secure — it does NOT satisfy
the PS's information-theoretic security requirement on its own. Message
authenticity is provided by the QDS layer (qds_signer / qds_verifier),
which offers information-theoretic security via quantum mechanics.
"""

from typing import Tuple, Any
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives import serialization


class ClassicalChannelAuth:
    """
    ML-DSA-65 authentication for the classical control channel.
    Used to protect session metadata and teleportation correction bits.
    """

    @staticmethod
    def generate_keys() -> Tuple[str, Any]:
        """
        Generates a real ML-DSA-65 keypair for classical channel protection.
        Returns (public_key_hex, private_key_object).
        """
        private_key = mldsa.MLDSA65PrivateKey.generate()
        public_key = private_key.public_key()

        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return pub_bytes.hex(), private_key

    @staticmethod
    def sign_correction_bits(correction_bits: str, session_id: str,
                             sequence_number: int, private_key: Any) -> str:
        """
        Signs the concatenated crz/crx correction bitstring with ML-DSA.

        This is critical: if Eve intercepts the classical channel and flips
        even one correction bit, Bob applies the wrong Pauli operator, ruining
        the statistical verification. This tag prevents that DoS attack.

        Args:
            correction_bits: Concatenated string of crz/crx bits (e.g., "01100110...")
            session_id: Current session identifier
            sequence_number: Message sequence number
            private_key: ML-DSA-65 private key object

        Returns:
            Hex-encoded ML-DSA signature
        """
        payload = f"{correction_bits}||{session_id}||{sequence_number}"
        signature = private_key.sign(payload.encode('utf-8'))
        return signature.hex()

    @staticmethod
    def verify_correction_bits(correction_bits: str, session_id: str,
                               sequence_number: int, auth_tag: str,
                               public_key_hex: str) -> bool:
        """
        Verifies the ML-DSA auth tag on the correction bits.
        Bob calls this BEFORE attempting quantum verification.
        """
        try:
            public_key_bytes = bytes.fromhex(public_key_hex)
            public_key = mldsa.MLDSA65PublicKey.from_public_bytes(public_key_bytes)
            signature_bytes = bytes.fromhex(auth_tag)
            payload = f"{correction_bits}||{session_id}||{sequence_number}"
            public_key.verify(signature_bytes, payload.encode('utf-8'))
            return True
        except Exception:
            return False

    @staticmethod
    def sign_session_metadata(session_id: str, challenge: str,
                              private_key: Any) -> str:
        """Signs session negotiation metadata with ML-DSA."""
        payload = f"SESSION||{session_id}||{challenge}"
        signature = private_key.sign(payload.encode('utf-8'))
        return signature.hex()

    @staticmethod
    def verify_session_metadata(session_id: str, challenge: str,
                                auth_tag: str, public_key_hex: str) -> bool:
        """Verifies session negotiation metadata auth tag."""
        try:
            public_key_bytes = bytes.fromhex(public_key_hex)
            public_key = mldsa.MLDSA65PublicKey.from_public_bytes(public_key_bytes)
            signature_bytes = bytes.fromhex(auth_tag)
            payload = f"SESSION||{session_id}||{challenge}"
            public_key.verify(signature_bytes, payload.encode('utf-8'))
            return True
        except Exception:
            return False
