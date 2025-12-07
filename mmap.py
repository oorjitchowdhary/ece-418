import random

class MMAPoracle:
    def __init__(self, k=96):
        self.k = k
        self.MOD = 2 ** k
        
        self.ID = random.getrandbits(k)
        self.IDP = random.getrandbits(k)
        self.K1 = random.getrandbits(k)
        self.K2 = random.getrandbits(k)
        self.K3 = random.getrandbits(k)
        self.K4 = random.getrandbits(k)

    def protocolRun(self):
        n1 = random.getrandbits(self.k)
        n2 = random.getrandbits(self.k)
        
        A = self.IDP ^ self.K1 ^ n1
        B = (self.IDP & self.K2) | n1
        C = (self.IDP + self.K3 + n2) % self.MOD
        
        n1_recovered = A ^ self.IDP ^ self.K1
        n2_recovered = (C - self.IDP - self.K3) % self.MOD
        
        B_check = (self.IDP & self.K2) | n1_recovered
        if B != B_check:
            return None, self
            
        D = (self.IDP | self.K4) & n2_recovered
        E = ((self.ID + self.IDP) % self.MOD) ^ n1_recovered
        
        self._update_keys(n1_recovered, n2_recovered)
        
        return {'A': A, 'B': B, 'C': C, 'D': D, 'E': E}, self

    def _update_keys(self, n1, n2):
        old_IDP = self.IDP
        old_K1 = self.K1
        old_K2 = self.K2
        old_K3 = self.K3
        old_K4 = self.K4
        
        self.IDP = ((old_IDP + (n1 ^ n2)) % self.MOD) ^ self.ID
        self.K1 = old_K1 ^ n2 ^ ((old_K3 + self.ID) % self.MOD)
        self.K2 = old_K2 ^ n2 ^ ((old_K4 + self.ID) % self.MOD)
        self.K3 = ((old_K3 ^ n1) + (old_K1 ^ self.ID)) % self.MOD
        self.K4 = ((old_K4 ^ n1) + (old_K2 ^ self.ID)) % self.MOD

    def verifyID(self, test_ID):
        return 1 if test_ID == self.ID else 0


def attack(oracle):
    """
    Exploit MMAP vulnerability: when (IDP)_i = 0, message B reveals (n1)_i = (B)_i.
    Use E = (ID + IDP) XOR n1 to recover ID bit-by-bit with carry propagation.
    """
    k = oracle.k
    runs = []
    curr_IDP = oracle.IDP
    
    for _ in range(64):
        out, _ = oracle.protocolRun()
        if out:
            runs.append((curr_IDP, out['B'], out['E']))
        curr_IDP = oracle.IDP
            
    known_ID = 0
    
    for bit in range(k):
        candidates = []
        
        for bit_val in [0, 1]:
            consistent = True
            current_ID_guess = known_ID | (bit_val << bit)
            count_checked = 0
            
            for IDP, B, E in runs:
                if not ((IDP >> bit) & 1):
                    count_checked += 1
                    sum_val = (current_ID_guess + IDP) % (1 << k)
                    n1_derived = E ^ sum_val
                    
                    if ((n1_derived >> bit) & 1) != ((B >> bit) & 1):
                        consistent = False
                        break
            
            if consistent and count_checked > 0:
                candidates.append(bit_val)
        
        if len(candidates) == 1:
            known_ID |= (candidates[0] << bit)
        else:
            known_ID |= (candidates[0] << bit) if candidates else 0
            
    return known_ID


def reconstruct_ID_from_runs(runs, k):
    """Reconstruct ID from MMAP runs using bit-by-bit recovery."""
    known_ID = 0

    for bit in range(k):
        candidates = []

        for bit_val in [0, 1]:
            consistent = True
            current_ID_guess = known_ID | (bit_val << bit)
            count_checked = 0

            for IDP, B, E in runs:
                if not ((IDP >> bit) & 1):
                    count_checked += 1
                    sum_val = (current_ID_guess + IDP) % (1 << k)
                    n1_derived = E ^ sum_val

                    if ((n1_derived >> bit) & 1) != ((B >> bit) & 1):
                        consistent = False
                        break

            if consistent and count_checked > 0:
                candidates.append(bit_val)

        if len(candidates) == 1:
            known_ID |= (candidates[0] << bit)
        elif not candidates:
            return None
        else:
            known_ID |= (candidates[0] << bit)

    return known_ID


def attack_min_runs_single(k=96, max_runs=128):
    """Find minimum runs needed to recover ID for a single MMAP oracle instance."""
    oracle = MMAPoracle(k=k)
    runs = []
    curr_IDP = oracle.IDP

    for r in range(1, max_runs + 1):
        out, _ = oracle.protocolRun()
        if out:
            runs.append((curr_IDP, out['B'], out['E']))
            curr_IDP = oracle.IDP

            ID_guess = reconstruct_ID_from_runs(runs, k)
            if ID_guess is not None and oracle.verifyID(ID_guess):
                return r
        else:
            curr_IDP = oracle.IDP

    print(f"[k={k}] Failed to recover ID within {max_runs} runs")
    return None


def experiment_scaling(k_values, trials=20, max_runs=128):
    """Estimate how required runs for MMAP attack scale with k."""
    results = {}

    print("Empirical scaling of MMAP attack (min runs over trials)")
    print("k (bits)\tavg runs\tmin\tmax\tfails")

    for k in k_values:
        run_counts = []
        fails = 0
        for _ in range(trials):
            r = attack_min_runs_single(k=k, max_runs=max_runs)
            if r is None:
                fails += 1
            else:
                run_counts.append(r)

        if run_counts:
            avg_runs = sum(run_counts) / len(run_counts)
            min_runs = min(run_counts)
            max_runs_result = max(run_counts)
        else:
            avg_runs = float('nan')
            min_runs = None
            max_runs_result = None

        results[k] = {
            "runs": run_counts,
            "avg": avg_runs,
            "min": min_runs,
            "max": max_runs_result,
            "fails": fails,
        }

        print(f"{k:7d}\t{avg_runs:8.2f}\t{min_runs}\t{max_runs_result}\t{fails}")

    return results