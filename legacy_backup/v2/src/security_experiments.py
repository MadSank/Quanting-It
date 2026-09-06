from typing import List, Dict, Any
from src.metrics import AttackType
from src.attack_simulator import AttackSimulator

class SecurityExperiments:
    """
    [EXPERIMENTAL HYBRID AUTHENTICATION FRAMEWORK]
    Runs comparisons between different authentication architectures.
    """
    
    def __init__(self):
        self.simulator = AttackSimulator(proof_length=8)
        
    def evaluate_architectures(self, result) -> Dict[str, bool]:
        """
        Given an AttackResult (where all layers were evaluated),
        determine if the attack would have been detected by each architecture.
        Returns a dict of { Architecture_Name : Detected (bool) }
        """
        det = result.details
        
        # A. Classical / PQ signature only (Checks: SESSION, REPLAY, HASH, PQ)
        arch_a = not (det.get("SESSION", True) and det.get("REPLAY", True) and det.get("CLASSICAL_HASH", True) and det.get("PQ_SIGNATURE", True))
        
        # B. Quantum fingerprint only (Checks: SESSION, REPLAY, QUANTUM_BINDING)
        arch_b = not (det.get("SESSION", True) and det.get("REPLAY", True) and det.get("QUANTUM_BINDING", True))
        
        # C. PQ + Quantum fingerprint (Checks: SESSION, REPLAY, HASH, PQ, QUANTUM_BINDING)
        arch_c = not (det.get("SESSION", True) and det.get("REPLAY", True) and det.get("CLASSICAL_HASH", True) and det.get("PQ_SIGNATURE", True) and det.get("QUANTUM_BINDING", True))
        
        # D. PQ + Quantum fingerprint + E91 (Checks: ALL)
        arch_d = result.detected
        
        # Special Case: Legitimate message shouldn't be "detected" as an attack.
        if result.attack_type == AttackType.NO_ATTACK:
            # Should be False for all (meaning no attack detected, message accepted)
            pass
            
        return {
            "A. Classical/PQ": arch_a,
            "B. Quantum Fingerprint Only": arch_b,
            "C. Hybrid (PQ + Fingerprint)": arch_c,
            "D. Hybrid + E91 Monitor": arch_d
        }
        
    def run_comparison(self) -> List[Dict[str, Any]]:
        attacks_to_test = [
            AttackType.NO_ATTACK,
            AttackType.MESSAGE_TAMPERING,
            AttackType.SIGNATURE_TAMPERING,
            AttackType.PROOF_SUBSTITUTION,
            AttackType.INTERCEPT_RESEND,
            AttackType.E91_CHANNEL_DISTURBANCE
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
