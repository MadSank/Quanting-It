import secrets

random = secrets.SystemRandom()  # CSPRNG for basis choices
import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

class E91Monitor:
    """
    [EXPERIMENTAL HYBRID AUTHENTICATION FRAMEWORK]
    
    This class implements an E91-inspired entanglement and correlation monitor.
    It does NOT implement a complete E91 QKD protocol.
    Instead, it monitors the integrity of the quantum channel by verifying
    that expected entanglement correlations (e.g., perfect correlation in matching bases)
    are maintained. Disturbance caused by Eve (e.g., intercept-resend) will 
    degrade these correlations and be detected.
    """
    # 400 pairs (about 200 compared): a full intercept-resend (about 25% errors)
    # stays under a 15% threshold with probability below 0.1%. With 100 pairs it was about 4%.
    def __init__(self, num_pairs: int = 400, error_threshold: float = 0.15):
        self.num_pairs = num_pairs
        self.error_threshold = error_threshold
        self.sim = AerSimulator()

    def measure_disturbance(self, attack_type: str = "NONE") -> dict:
        """
        Simulates the distribution and measurement of Bell pairs over the channel.
        Alice and Bob randomly choose measurement bases (Z or X).
        If attack_type == "INTERCEPT_RESEND", Eve intercepts, measures in a random basis, 
        and sends the collapsed state to Bob.
        Returns the correlation error rate for matched bases.
        """
        alice_bases = [random.choice(['Z', 'X']) for _ in range(self.num_pairs)]
        bob_bases = [random.choice(['Z', 'X']) for _ in range(self.num_pairs)]
        
        if attack_type == "INTERCEPT_RESEND":
            eve_bases = [random.choice(['Z', 'X']) for _ in range(self.num_pairs)]
        
        errors = 0
        matches = 0
        circuits = []

        for i in range(self.num_pairs):
            # 1. Prepare Bell pair |Phi+> = (|00> + |11>)/sqrt(2)
            qc = QuantumCircuit(2, 2)
            qc.h(0)
            qc.cx(0, 1)

            # 2. Eve intercepts (optional): measures in her basis, the state collapses
            if attack_type == "INTERCEPT_RESEND":
                if eve_bases[i] == 'X':
                    qc.h(1)
                qc.measure(1, 1)
                if eve_bases[i] == 'X':
                    qc.h(1)

            # 3. Alice and 4. Bob measure in their own bases
            if alice_bases[i] == 'X':
                qc.h(0)
            qc.measure(0, 0)
            if bob_bases[i] == 'X':
                qc.h(1)
            qc.measure(1, 1)
            circuits.append(qc)

        # One batched simulator call instead of one per pair, so a sample large
        # enough to catch an eavesdropper reliably stays fast.
        result = self.sim.run(circuits, shots=1).result()
        for i in range(self.num_pairs):
            # Qiskit bit order: outcome[0] is Bob (clbit 1), outcome[1] is Alice (clbit 0)
            outcome = list(result.get_counts(i).keys())[0]
            bob_res, alice_res = outcome[0], outcome[1]
            if alice_bases[i] == bob_bases[i]:
                matches += 1
                if alice_res != bob_res:
                    errors += 1

        if matches == 0:
            error_rate = 0.0 # Avoid division by zero, though statistically unlikely
        else:
            error_rate = errors / matches
            
        return {
            "error_rate": error_rate,
            "detected": error_rate > self.error_threshold,
            "matches": matches,
            "errors": errors
        }

    def verify_channel_integrity(self, error_rate: float) -> bool:
        """
        Returns True if the channel error rate is within the acceptable threshold.
        """
        return error_rate <= self.error_threshold

    def measure_chsh(
        self,
        shots: int = 4096,
        attack_type: str = "NONE",
        attack_params: dict = None,
        backend_executor: any = None,
        seed_simulator: int = None,
    ):
        """
        Executes a 4-setting CHSH Bell test to monitor channel non-locality and entanglement.
        Returns a CHSHResult object.
        """
        from src.chsh import run_chsh_experiment
        return run_chsh_experiment(
            shots=shots,
            attack_type=attack_type,
            attack_params=attack_params,
            backend_executor=backend_executor,
            seed_simulator=seed_simulator,
        )

