from src.attack_simulator import AttackSimulator
from src.metrics import AttackType
from src.e91_monitor import E91Monitor
import time

def run_demo():
    print("====================================================")
    print(" HYBRID POST-QUANTUM + QUANTUM AUTHENTICATION DEMO ")
    print("====================================================")
    
    sim = AttackSimulator(n_qubits=8)
    
    print("\n[SCENARIO 1: LEGITIMATE MESSAGE]")
    print("Alice sends legitimate message.")
    res = sim.run_attack(AttackType.NO_ATTACK, "scen1")
    if res.rejection_code == "ACCEPTED":
        print("Bob ACCEPTS. (Session, Sequence, Hash, ML-DSA, Fingerprint, E91 verified)")
    else:
        print(f"Bob REJECTS: {res.rejection_code}")
    
    print("\n[SCENARIO 2: MESSAGE TAMPERING]")
    print("Eve changes the message.")
    res = sim.run_attack(AttackType.MESSAGE_TAMPERING, "scen2")
    print(f"Bob REJECTS because {res.detection_layer} validation failed (Code: {res.rejection_code}).")
    
    print("\n[SCENARIO 3: REPLAY ATTACK]")
    print("Eve replays an old packet.")
    res = sim.run_attack(AttackType.REPLAY, "scen3")
    print(f"Bob REJECTS because of {res.detection_layer} (Code: {res.rejection_code}).")
    
    print("\n[SCENARIO 4: QUANTUM CHANNEL INTERCEPTION]")
    print("Eve intercepts the quantum channel (Intercept/Resend).")
    res = sim.run_attack(AttackType.INTERCEPT_RESEND, "scen4")
    if res.detected:
        print(f"Bob REJECTS because {res.detection_layer} detected disturbance (Code: {res.rejection_code}).")
    else:
        print("Bob ACCEPTS (Attack undetected under current basis combination).")
        
    print("\n[SCENARIO 5: E91 CHANNEL INTEGRITY MONITORING]")
    print("Monitoring Bell-state correlation on clean vs noisy channels:")
    monitor = E91Monitor(num_pairs=50, error_threshold=0.15)
    clean_res = monitor.measure_disturbance(attack_type="NONE")
    print(f"Clean Channel Error Rate: {clean_res['error_rate']:.3f} (Detected: {clean_res['detected']})")
    attack_res = monitor.measure_disturbance(attack_type="INTERCEPT_RESEND")
    print(f"Under Intercept-Resend:   {attack_res['error_rate']:.3f} (Detected: {attack_res['detected']})")
    
    print("\n====================================================")
    print(" DEMO COMPLETE")
    print("====================================================")

if __name__ == "__main__":
    run_demo()

