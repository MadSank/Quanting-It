from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class QuantumProof:
    """
    Structured QuantumProof object. Contains only information legitimately required by simulation.
    """
    proof_id: str
    session_id: str
    sequence_number: int
    proof_length: int
    teleportation_metadata: List[Dict[str, Any]]
    resource_identifiers: List[int]
