"""
Classical hashing and transcript encoding for the legacy (v0) packet.

Every multi-field input is encoded unambiguously: a domain tag, then each
field as a 4-byte big-endian length followed by its bytes. Two different
field tuples can never produce the same byte string, so a value cannot be
shifted from one field into its neighbour (the old f-string concatenation
allowed that).
"""

import hashlib
import hmac
import secrets
from typing import Iterable

HASH_DOMAIN = b"quatinit/v0/message-hash/2"
TRANSCRIPT_DOMAIN = b"quatinit/v0/transcript/2"


def _field(value) -> bytes:
    if isinstance(value, bytes):
        data = value
    elif isinstance(value, int):
        data = str(value).encode("ascii")
    else:
        data = str(value).encode("utf-8")
    return len(data).to_bytes(4, "big") + data


def encode_fields(domain: bytes, fields: Iterable) -> bytes:
    """Injective encoding: domain tag, then length-prefixed fields."""
    return _field(domain) + b"".join(_field(f) for f in fields)


def generate_challenge() -> str:
    """Generate a 256-bit (32 byte) secure random challenge as a hex string."""
    return secrets.token_hex(32)


def compute_message_hash(message: str, session_id: str, challenge: str, sequence_number: int) -> str:
    """
    SHA-256 over the unambiguous encoding of
    (message, session_id, challenge, sequence_number).
    """
    data = encode_fields(HASH_DOMAIN, [message, session_id, challenge, int(sequence_number)])
    return hashlib.sha256(data).hexdigest()


def verify_message_hash(message: str, session_id: str, challenge: str, sequence_number: int, expected_hash: str) -> bool:
    """Constant-time comparison of the recomputed hash with the received one."""
    actual_hash = compute_message_hash(message, session_id, challenge, sequence_number)
    return hmac.compare_digest(actual_hash, str(expected_hash))


def canonical_transcript(session_id: str, sequence_number: int, message_hash: str,
                         revealed_keys: list, message_bits: list, n_positions: int,
                         fingerprint_qubits: int) -> bytes:
    """
    The bytes Alice signs with ML-DSA and Bob verifies.

    Covers the session, sequence number, message hash, every revealed GC key
    (via a SHA-256 over all of them, in order), the message bits and the
    signature parameters. Changing any of these invalidates the ML-DSA tag.
    """
    keys_digest = hashlib.sha256(b"".join(_field(k) for k in revealed_keys)).hexdigest()
    bits = "".join(str(int(b)) for b in message_bits)
    return encode_fields(TRANSCRIPT_DOMAIN, [
        session_id, int(sequence_number), message_hash, keys_digest, bits,
        int(n_positions), int(fingerprint_qubits),
    ])
