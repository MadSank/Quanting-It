import hashlib
import secrets

def generate_challenge() -> str:
    """Generate a 256-bit (32 byte) secure random challenge as a hex string."""
    return secrets.token_hex(32)

def compute_message_hash(message: str, session_id: str, challenge: str, sequence_number: int) -> str:
    """
    Computes the SHA-256 hash of the message context.
    Context: message || session_id || challenge || sequence_number
    """
    context = f"{message}{session_id}{challenge}{sequence_number}"
    return hashlib.sha256(context.encode('utf-8')).hexdigest()

def verify_message_hash(message: str, session_id: str, challenge: str, sequence_number: int, expected_hash: str) -> bool:
    """
    Verifies the expected hash matches the newly computed hash.
    """
    actual_hash = compute_message_hash(message, session_id, challenge, sequence_number)
    return actual_hash == expected_hash
