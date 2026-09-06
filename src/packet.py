from dataclasses import dataclass, field
from typing import Any, Dict, Optional

@dataclass
class SecurePacket:
    session_id: str
    sequence_number: int
    message: str
    message_hash: str
    qds_signature: Optional[Any] = None        # QDSSignature object
    classical_auth_tag: Optional[str] = None    # ML-DSA tag for session metadata
    ml_dsa_signature: Optional[str] = None      # REAL ML-DSA tag over the canonical transcript
    metadata: Dict[str, Any] = field(default_factory=dict)
