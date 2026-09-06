from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from src.quantum_fingerprint import QuantumFingerprint

@dataclass
class SecurePacket:
    session_id: str
    sequence_number: int
    message: str
    message_hash: str
    pq_signature: Optional[str] = None
    pq_public_key: Optional[str] = None
    quantum_fingerprint: Optional[QuantumFingerprint] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
