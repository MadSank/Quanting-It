from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
import enum
from src.threat_engine import ThreatScore

class DefenseStatus(enum.Enum):
    """Honest classification of security mechanism against an attack."""
    PREVENTED = "PREVENTED"          # Structurally prevented by protocol constraints (e.g. Holevo information bound, copy budget)
    DETECTED = "DETECTED"            # Detected by statistical test or verification layer
    MITIGATED = "MITIGATED"          # Impact bounded/tolerated by design (e.g. noise margin)
    NOT_DETECTABLE = "NOT_DETECTABLE" # Cannot be detected at this layer
    OUT_OF_SCOPE = "OUT_OF_SCOPE"    # Beyond threat model (e.g. side-channel, long-term memory)

class AttackType(enum.Enum):
    NO_ATTACK = "NO_ATTACK"
    MESSAGE_TAMPERING = "MESSAGE_TAMPERING"
    HASH_TAMPERING = "HASH_TAMPERING"
    FORGERY_ATTEMPT = "FORGERY_ATTEMPT"
    IMPERSONATION = "IMPERSONATION"
    SEQUENCE_TAMPERING = "SEQUENCE_TAMPERING"
    REPLAY = "REPLAY"
    QUANTUM_X = "QUANTUM_X"
    QUANTUM_Z = "QUANTUM_Z"
    QUANTUM_Y = "QUANTUM_Y"
    QUANTUM_DEPOLARIZING = "QUANTUM_DEPOLARIZING"
    INTERCEPT_RESEND = "INTERCEPT_RESEND"
    PROOF_SUBSTITUTION = "PROOF_SUBSTITUTION"
    RESOURCE_REUSE = "RESOURCE_REUSE"
    COMPROMISED_SESSION_CONTEXT = "COMPROMISED_SESSION_CONTEXT"
    CROSS_SESSION_REUSE = "CROSS_SESSION_REUSE"
    E91_CHANNEL_DISTURBANCE = "E91_CHANNEL_DISTURBANCE"
    SIGNATURE_TAMPERING = "SIGNATURE_TAMPERING"
    # GC QDS specific attacks
    KEY_SUBSTITUTION = "KEY_SUBSTITUTION"
    COPY_EXHAUSTION = "COPY_EXHAUSTION"
    UNAUTHORIZED_VERIFICATION = "UNAUTHORIZED_VERIFICATION"
    REPUDIATION_ATTEMPT = "REPUDIATION_ATTEMPT"
    TRANSFERABILITY_ATTACK = "TRANSFERABILITY_ATTACK"
    HOLEVO_EXHAUSTION = "HOLEVO_EXHAUSTION"

@dataclass
class AttackResult:
    attack_id: str
    attack_type: AttackType
    attack_successful: bool
    detected: bool
    detection_layer: str  # e.g., "CLASSICAL_HASH", "QDS_VERIFICATION", "REPLAY_PROTECTION", "E91_CHANNEL"
    rejection_code: str
    threat_score: Optional[ThreatScore] = None
    defense_status: DefenseStatus = DefenseStatus.DETECTED
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def qds_result(self) -> Optional[Any]:
        return self.details.get("qds_result")

class SecurityMetrics:
    def __init__(self):
        self.total_attacks = 0
        self.attacks_detected = 0
        self.attacks_undetected = 0
        self.results: List[AttackResult] = []
        
    def record_attack_result(self, result: AttackResult):
        self.total_attacks += 1
        self.results.append(result)
        if result.detected:
            self.attacks_detected += 1
        else:
            self.attacks_undetected += 1
            
    def get_summary(self) -> Dict[str, Any]:
        detection_rate = (self.attacks_detected / self.total_attacks) if self.total_attacks > 0 else 0.0
        by_type = {}
        for r in self.results:
            t = r.attack_type.name
            if t not in by_type:
                by_type[t] = {"total": 0, "detected": 0}
            by_type[t]["total"] += 1
            if r.detected:
                by_type[t]["detected"] += 1
                
        return {
            "total_attacks": self.total_attacks,
            "attacks_detected": self.attacks_detected,
            "attacks_undetected": self.attacks_undetected,
            "detection_rate": detection_rate,
            "results_by_type": by_type
        }
