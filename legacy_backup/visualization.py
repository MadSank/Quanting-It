"""
Visualization Helper Functions for Teleportation & QDS Cyber Threat Analytics.

Generates Matplotlib plots for:
1. Legitimate vs Attacked Measurement Outcome Distributions
2. Attack Strength Sensitivity Curves (Attack Strength vs QBER & Verification Rate)
3. Quantum Teleportation Circuit Diagram Rendering
"""

import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, Any, List

# Set clean aesthetic plot style
plt.style.use('seaborn-v0_8-whitegrid' if 'seaborn-v0_8-whitegrid' in plt.style.available else 'default')


def plot_measurement_distribution(legit_metrics: Dict[str, Any], attacked_metrics: Dict[str, Any] = None) -> plt.Figure:
    """
    Plots comparative bar charts of Bob's verification outcomes ('0' = Success, '1' = Error).
    """
    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=120)

    categories = ['Correct Reconstruction (|0⟩)', 'State Error (|1⟩)']
    
    legit_bob = legit_metrics['bob_counts']
    legit_vals = [legit_bob.get('0', 0), legit_bob.get('1', 0)]
    legit_pct = [v / max(1, legit_metrics['total_shots']) * 100 for v in legit_vals]

    x = np.arange(len(categories))
    width = 0.35

    rects1 = ax.bar(x - width/2 if attacked_metrics else x, legit_pct, width if attacked_metrics else 0.5,
                   label='Legitimate (p=0.0)', color='#10B981', alpha=0.85, edgecolor='black', linewidth=1)

    if attacked_metrics:
        attack_bob = attacked_metrics['bob_counts']
        attack_vals = [attack_bob.get('0', 0), attack_bob.get('1', 0)]
        attack_pct = [v / max(1, attacked_metrics['total_shots']) * 100 for v in attack_vals]

        p_str = attacked_metrics.get('attack_strength', '')
        attack_name = attacked_metrics.get('attack_type', 'Attack')
        label_str = f"Attacked ({attack_name}, p={p_str})" if p_str != '' else f"Attacked ({attack_name})"

        rects2 = ax.bar(x + width/2, attack_pct, width,
                       label=label_str, color='#EF4444', alpha=0.85, edgecolor='black', linewidth=1)

        # Add bar text labels
        ax.bar_label(rects2, fmt='%.1f%%', padding=3, fontsize=9)

    ax.bar_label(rects1, fmt='%.1f%%', padding=3, fontsize=9)

    ax.set_ylabel('Percentage of Shots (%)', fontsize=11, fontweight='bold')
    ax.set_title('Bob Verification Measurement Distribution (QBER Analysis)', fontsize=12, fontweight='bold', pad=12)
    ax.set_xticks(x)
    ax.set_xticklabels(categories, fontsize=10, fontweight='bold')
    ax.set_ylim(0, 115)
    ax.legend(frameon=True, facecolor='white', framealpha=0.9, fontsize=10)
    plt.tight_layout()

    return fig


def plot_attack_sensitivity_curves(sweep_results: List[Dict[str, Any]], threshold_qber: float = 0.05) -> plt.Figure:
    """
    Plots Sensitivity Curves: Attack Strength (p) vs QBER & Verification Success Rate.

    Args:
        sweep_results: List of dicts with keys 'attack_strength', 'qber', 'fidelity', 'threat_detected'
        threshold_qber: Statistical threshold line to overlay
    """
    p_vals = [r['attack_strength'] for r in sweep_results]
    qber_vals = [r['qber'] for r in sweep_results]
    vsr_vals = [r['fidelity'] * 100 for r in sweep_results]
    detected_mask = [r['threat_detected'] for r in sweep_results]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.5), dpi=120)

    # Plot 1: Attack Strength vs QBER
    ax1.plot(p_vals, qber_vals, 'o-', color='#3B82F6', linewidth=2.5, markersize=6, label='Observed QBER')
    ax1.axhline(threshold_qber, color='#DC2626', linestyle='--', linewidth=1.8, label=f'Detector Threshold ({threshold_qber:.3f})')
    
    # Highlight detection zone
    ax1.fill_between(p_vals, qber_vals, threshold_qber, where=[q > threshold_qber for q in qber_vals],
                     color='#FEE2E2', alpha=0.5, label='Attack Detected Zone')

    ax1.set_xlabel('Adversary Attack Strength (p)', fontsize=10, fontweight='bold')
    ax1.set_ylabel('Quantum Bit Error Rate (QBER)', fontsize=10, fontweight='bold')
    ax1.set_title('Attack Strength vs. QBER', fontsize=11, fontweight='bold')
    ax1.set_ylim(-0.02, max(1.0, max(qber_vals) * 1.1))
    ax1.legend(frameon=True, fontsize=9)

    # Plot 2: Attack Strength vs Verification Success Rate
    ax2.plot(p_vals, vsr_vals, 's-', color='#10B981', linewidth=2.5, markersize=6, label='Verification Success Rate (%)')
    ax2.set_xlabel('Adversary Attack Strength (p)', fontsize=10, fontweight='bold')
    ax2.set_ylabel('Verification Success Rate (%)', fontsize=10, fontweight='bold')
    ax2.set_title('Signature Verification Rate Degradation', fontsize=11, fontweight='bold')
    ax2.set_ylim(-2, 105)
    ax2.legend(frameon=True, fontsize=9)

    plt.tight_layout()
    return fig


def plot_alice_measurement_distribution(alice_counts: Dict[str, int]) -> plt.Figure:
    """
    Plots Alice's Bell Measurement outcome distribution across the 4 Bell states (00, 01, 10, 11).
    """
    fig, ax = plt.subplots(figsize=(6, 3.8), dpi=120)
    
    states = ['00 (|Φ+⟩)', '01 (|Ψ+⟩)', '10 (|Φ-⟩)', '11 (|Ψ-⟩)']
    keys = ['00', '01', '10', '11']
    vals = [alice_counts.get(k, 0) for k in keys]
    total = max(1, sum(vals))
    pcts = [v / total * 100 for v in vals]

    bars = ax.bar(states, pcts, color='#6366F1', alpha=0.85, edgecolor='black', linewidth=1)
    ax.bar_label(bars, fmt='%.1f%%', padding=3, fontsize=9)

    ax.set_ylabel('Percentage of Shots (%)', fontsize=10, fontweight='bold')
    ax.set_title("Alice's Bell Measurement Outcome Distribution", fontsize=11, fontweight='bold')
    ax.set_ylim(0, max(pcts, default=25) * 1.25)
    plt.tight_layout()

    return fig
