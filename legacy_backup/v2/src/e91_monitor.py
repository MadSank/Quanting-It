import random
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
    def __init__(self, num_pairs: int = 50, error_threshold: float = 0.15):
        self.num_pairs = num_pairs
        self.error_threshold = error_threshold
        self.sim = AerSimulator()

    def simulate_channel(self, attack_type: str = "NONE") -> float:
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

        for i in range(self.num_pairs):
            # 1. Prepare Bell pair |Φ+> = (|00> + |11>)/sqrt(2)
            qc = QuantumCircuit(2, 2)
            qc.h(0)
            qc.cx(0, 1)

            # 2. Eve intercepts (optional)
            if attack_type == "INTERCEPT_RESEND":
                if eve_bases[i] == 'X':
                    qc.h(1) # Eve's measurement in X basis
                qc.measure(1, 1)
                # To simulate sending the state forward without retaining the full quantum state
                # we just let the simulator collapse it via measurement before Bob measures.
                if eve_bases[i] == 'X':
                    qc.h(1) # Revert basis for Bob's measurement

            # 3. Alice measures qubit 0
            if alice_bases[i] == 'X':
                qc.h(0)
            qc.measure(0, 0)
            
            # 4. Bob measures qubit 1
            if bob_bases[i] == 'X':
                qc.h(1)
            qc.measure(1, 1)

            # Run simulation
            result = self.sim.run(qc, shots=1).result()
            counts = result.get_counts()
            
            # Outcome format depends on bit string. e.g. '01' means Bob=0, Alice=1 (Qiskit uses little endian)
            outcome = list(counts.keys())[0]
            bob_res = outcome[0]
            alice_res = outcome[1]

            # 5. Check correlations if bases match
            if alice_bases[i] == bob_bases[i]:
                matches += 1
                if alice_res != bob_res:
                    errors += 1

        if matches == 0:
            return 0.0 # Avoid division by zero, though statistically unlikely
            
        error_rate = errors / matches
        return error_rate

    def verify_channel_integrity(self, error_rate: float) -> bool:
        """
        Returns True if the channel error rate is within the acceptable threshold.
        """
        return error_rate <= self.error_threshold
