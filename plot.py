import pandas as pd
import matplotlib.pyplot as plt

# 1. Load the data
try:
    baseline = pd.read_csv('baseline_results.csv')
    enforced = pd.read_csv('enforced_results.csv')
except FileNotFoundError as e:
    print(f"Error loading CSV files: {e}")
    print("Ensure 'baseline_results.csv' and 'enforced_results.csv' are in the same directory.")
    exit(1)

# 2. Set up the figure layout (Side-by-side for IEEE/publication format)
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
fig.suptitle('eBPF Syscall Enforcer Performance Overhead Analysis', fontsize=16, fontweight='bold')

# --- Plot 1: Throughput (RPS) ---
# Higher is better
ax1.plot(baseline['Requests'], baseline['Throughput'], label='Baseline (No eBPF)', marker='o', linestyle='-', color='#1f77b4', linewidth=2)
ax1.plot(enforced['Requests'], enforced['Throughput'], label='Enforced (eBPF Active)', marker='s', linestyle='--', color='#d62728', linewidth=2)
ax1.set_title('Throughput vs. Load Volume', fontsize=14)
ax1.set_xlabel('Total Requests Initiated', fontsize=12)
ax1.set_ylabel('Throughput (Requests Per Second)', fontsize=12)
ax1.grid(True, linestyle=':', alpha=0.7)
ax1.legend(fontsize=11)

# --- Plot 2: Mean Latency ---
# Lower is better
ax2.plot(baseline['Requests'], baseline['MeanLatency'], label='Baseline (No eBPF)', marker='o', linestyle='-', color='#1f77b4', linewidth=2)
ax2.plot(enforced['Requests'], enforced['MeanLatency'], label='Enforced (eBPF Active)', marker='s', linestyle='--', color='#d62728', linewidth=2)
ax2.set_title('Mean Latency vs. Load Volume', fontsize=14)
ax2.set_xlabel('Total Requests Initiated', fontsize=12)
ax2.set_ylabel('Mean Latency (Milliseconds)', fontsize=12)
ax2.grid(True, linestyle=':', alpha=0.7)
ax2.legend(fontsize=11)

# 3. Format and Save
plt.tight_layout()
plt.subplots_adjust(top=0.88) # Adjust top to make room for the suptitle
plt.savefig('performance_comparison_graph.png', dpi=300, bbox_inches='tight')
print("Success! Graph saved as 'performance_comparison_graph.png'.")


