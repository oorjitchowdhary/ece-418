import matplotlib.pyplot as plt

from mmap import MMAPoracle, attack as mmap_attack, experiment_scaling as mmap_experiment_scaling
from emap import EMAPoracle, attack as emap_attack, experiment_scaling as emap_experiment_scaling


def plot_empirical_mmap_vs_emap(k_values, trials=20, max_runs_mmap=128):
    """Compare MMAP vs EMAP attacks empirically and plot results."""
    mmap_results = mmap_experiment_scaling(k_values=k_values, trials=trials, max_runs=max_runs_mmap)
    mmap_avg = [mmap_results[k]["avg"] for k in k_values]

    emap_results = emap_experiment_scaling(k_values=k_values, trials=trials)
    emap_avg = [emap_results[k]["avg"] for k in k_values]

    plt.figure()
    plt.plot(k_values, mmap_avg, marker='o', label='MMAP (empirical)')
    plt.plot(k_values, emap_avg, marker='x', linestyle='--',
             label='EMAP (empirical)')
    plt.xlabel("Key length k (bits)")
    plt.ylabel("Average protocol runs to recover ID")
    plt.title("Empirical scaling of attacks on MMAP vs EMAP")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()


if __name__ == "__main__":
    print("Testing MMAP Attack...")
    mmap_oracle = MMAPoracle()
    recovered_id = mmap_attack(mmap_oracle)
    print(f"Actual ID: {mmap_oracle.ID}")
    print(f"Recovered: {recovered_id}")
    print(f"Success: {recovered_id == mmap_oracle.ID}")
    
    print("\nTesting EMAP Attack...")
    emap_oracle = EMAPoracle()
    recovered_id_emap = emap_attack(emap_oracle)
    print(f"Actual ID: {emap_oracle.ID}")
    print(f"Recovered: {recovered_id_emap}")
    print(f"Success: {recovered_id_emap == emap_oracle.ID}")

    print("\nPlot MMAP vs EMAP empirical runs:")
    plot_empirical_mmap_vs_emap(k_values=[32, 64, 96, 128], trials=20, max_runs_mmap=128)
