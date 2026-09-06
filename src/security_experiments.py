from typing import List, Dict, Any
from src.metrics import AttackType
from src.attack_simulator import AttackSimulator

class SecurityExperiments:
    """
    [QUANTUM-INSPIRED THREAT DETECTION FRAMEWORK]
    Runs comparisons between different authentication architectures.
    """
    
    def __init__(self, n_qubits: int = 64):
        self.simulator = AttackSimulator(n_qubits=n_qubits)
        
    def evaluate_architectures(self, result) -> Dict[str, bool]:
        """
        Given an AttackResult, determine if the attack would have been
        detected by each architecture based on the detection layer.
        """
        layer = result.detection_layer
        
        # A. Classical Hash + Sequence Only
        arch_a = layer in ["CLASSICAL_HASH", "SESSION_STATE", "REPLAY_PROTECTION"]
        
        # B. Pure PQC Signature (simulated via ML-DSA on classical channel layer)
        arch_b = arch_a or layer == "CORRECTION_BITS" # In our mapping, ML-DSA fails on correction bits
        
        # C. QDS Only (No E91)
        arch_c = arch_a or layer == "QDS_VERIFICATION"
        
        # D. QDS + E91 Monitor (The full proposed framework)
        arch_d = result.detected
        
        if result.attack_type == AttackType.NO_ATTACK:
            arch_a = arch_b = arch_c = arch_d = False
            
        return {
            "A. Classical Only": arch_a,
            "B. PQC Signature": arch_b,
            "C. QDS (No E91)": arch_c,
            "D. QDS + E91 (Proposed)": arch_d
        }
        
    def run_comparison(self) -> List[Dict[str, Any]]:
        attacks_to_test = [
            AttackType.NO_ATTACK,
            AttackType.MESSAGE_TAMPERING,
            AttackType.FORGERY_ATTEMPT,
            AttackType.IMPERSONATION,
            AttackType.INTERCEPT_RESEND,
            AttackType.E91_CHANNEL_DISTURBANCE,
            AttackType.COMPROMISED_SESSION_CONTEXT
        ]
        
        report = []
        for i, attack in enumerate(attacks_to_test):
            res = self.simulator.run_attack(attack, f"EXP_{i}")
            eval_res = self.evaluate_architectures(res)
            
            report.append({
                "attack": attack.name,
                "architectures": eval_res
            })
            
        return report
