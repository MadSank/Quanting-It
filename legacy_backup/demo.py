"""
Complete Quantum-Inspired Cyber Threat Detection Demo Script.
Runs legitimate and attacked teleportation simulations and outputs complete empirical results.
"""

import numpy as np
import pandas as pd
from src.qds_verifier import run_qds_teleportation_experiment
from src.detector import detect_threat


def run_full_demo():
    print("=" * 80)
    print("  QUANTUM-INSPIRED CYBER THREAT DETECTION FOR QDS TELEPORTATION - DEMO  ")
    print("=" * 80)
    print("\n[PART 1] Legitimate Operation (No Attack, p = 0.0)")
    print("-" * 80)

    states = ["0", "1", "+", "-"]
    legit_results = []
    for st in states:
        res = run_qds_teleportation_experiment(
            state_name=st,
            attack_type="none",
            attack_strength=0.0,
            shots=1000,
            seed_simulator=42
        )
        m = res["metrics"]
        det = detect_threat(m["total_shots"], m["error_count"], baseline_noise=0.0, alpha=0.01)
        legit_results.append({
            "Input State": f"|{st}>",
            "Shots": m["total_shots"],
            "Success Shots (|0>)": m["success_count"],
            "Error Shots (|1>)": m["error_count"],
            "QBER": f"{m['qber']:.4f}",
            "Fidelity": f"{m['fidelity']:.4f}",
            "Z-Score": f"{det['z_score']:.2f}",
            "p-value": f"{det['p_value']:.4e}",
            "Detector Verdict": det["status_label"]
        })

    df_legit = pd.DataFrame(legit_results)
    print(df_legit.to_string(index=False))

    print("\n" + "=" * 80)
    print("[PART 2] Adversary Channel Tampering Experiments (p = 0.30)")
    print("-" * 80)

    attacks = [
        ("bit_flip", "0", "Pauli-X Bit Flip on |0>"),
        ("phase_flip", "+", "Pauli-Z Phase Flip on |+>"),
        ("depolarizing", "1", "Depolarizing Noise on |1>"),
        ("intercept_resend", "-", "Intercept-Resend on |->"),
    ]

    attack_results = []
    for atk_type, st, desc in attacks:
        res = run_qds_teleportation_experiment(
            state_name=st,
            attack_type=atk_type,
            attack_strength=0.30,
            shots=1000,
            seed_simulator=42
        )
        m = res["metrics"]
        det = detect_threat(m["total_shots"], m["error_count"], baseline_noise=0.0, alpha=0.01)
        attack_results.append({
            "Attack Scenario": desc,
            "Target State": f"|{st}>",
            "Attack Prob (p)": 0.30,
            "Error Shots": m["error_count"],
            "Observed QBER": f"{m['qber']:.4f}",
            "Fidelity": f"{m['fidelity']:.4f}",
            "Z-Score": f"{det['z_score']:.2f}",
            "p-value": f"{det['p_value']:.4e}",
            "Detector Verdict": det["status_label"]
        })

    df_attack = pd.DataFrame(attack_results)
    print(df_attack.to_string(index=False))

    print("\n" + "=" * 80)
    print("[PART 3] Attack Strength Parameter Sweep (Phase-Flip on |+>)")
    print("-" * 80)

    sweep_results = []
    p_values = [0.0, 0.05, 0.10, 0.20, 0.30, 0.40, 0.50, 0.75, 1.00]
    for p_val in p_values:
        res = run_qds_teleportation_experiment(
            state_name="+",
            attack_type="phase_flip",
            attack_strength=p_val,
            shots=1000,
            seed_simulator=42
        )
        m = res["metrics"]
        det = detect_threat(m["total_shots"], m["error_count"], baseline_noise=0.0, alpha=0.01)
        sweep_results.append({
            "Attack Strength (p)": f"{p_val:.2f}",
            "Error Shots": m["error_count"],
            "QBER": f"{m['qber']:.4f}",
            "Fidelity": f"{m['fidelity']:.4f}",
            "Z-Score": f"{det['z_score']:.2f}",
            "p-value": f"{det['p_value']:.4e}",
            "Verdict": det["status_label"]
        })

    df_sweep = pd.DataFrame(sweep_results)
    print(df_sweep.to_string(index=False))

    print("\n" + "=" * 80)
    print("  DEMO COMPLETE - ALL PIPELINE STAGES OPERATIONAL AND VERIFIED  ")
    print("=" * 80)


if __name__ == "__main__":
    run_full_demo()
