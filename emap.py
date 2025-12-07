import random

class EMAPoracle:
    def __init__(self, k=96):
        self.k = k
        self.run_count = 0
        
        self.ID = random.getrandbits(k)
        self.IDS = random.getrandbits(k)
        self.K1 = random.getrandbits(k)
        self.K2 = random.getrandbits(k)
        self.K3 = random.getrandbits(k)
        self.K4 = random.getrandbits(k)

    def F_p(self, z):
        """Compute parity bit for each 4-bit block of z. Returns k/4 parity bits."""
        result = 0
        num_blocks = self.k // 4
        for i in range(num_blocks):
            block = (z >> (i * 4)) & 0xF
            parity = (block >> 3) ^ (block >> 2) ^ (block >> 1) ^ block
            parity &= 1
            result |= (parity << i)
        return result

    def protocolRun1(self):
        self.run_count += 1
        
        n1 = random.getrandbits(self.k)
        n2 = random.getrandbits(self.k)
        
        A = self.IDS ^ self.K1 ^ n1
        B = (self.IDS | self.K2) ^ n1
        C = self.IDS ^ self.K3 ^ n2
        
        n1_recovered = A ^ self.IDS ^ self.K1
        n2_recovered = C ^ self.IDS ^ self.K3
        
        B_check = (self.IDS | self.K2) ^ n1_recovered
        if B != B_check:
            return None, self
            
        D = (self.IDS & self.K4) ^ n2_recovered
        
        term = (self.IDS & n1_recovered) | n2_recovered
        E = term ^ self.ID ^ self.K1 ^ self.K2 ^ self.K3 ^ self.K4
        
        self._update_keys(n1_recovered, n2_recovered)
        
        return {'A': A, 'B': B, 'C': C, 'D': D, 'E': E}, self

    def impersonate_reader(self, A, B, C):
        """Active attack simulation (Stage 2). Returns D, E responses for tag impersonation."""
        n1_recovered = A ^ self.IDS ^ self.K1
        n2_recovered = C ^ self.IDS ^ self.K3
        
        B_check = (self.IDS | self.K2) ^ n1_recovered
        if B != B_check:
            return None, None, self
            
        D = (self.IDS & self.K4) ^ n2_recovered
        term = (self.IDS & n1_recovered) | n2_recovered
        E = term ^ self.ID ^ self.K1 ^ self.K2 ^ self.K3 ^ self.K4
        
        self._update_keys(n1_recovered, n2_recovered)
        
        return D, E, self

    def _update_keys(self, n1, n2):
        half_k = self.k // 2
        quarter_k = self.k // 4
        
        ID_MSB = (self.ID >> half_k) & ((1 << half_k) - 1)
        ID_LSB = self.ID & ((1 << half_k) - 1)
        
        Fp_K1 = self.F_p(self.K1)
        Fp_K2 = self.F_p(self.K2)
        Fp_K3 = self.F_p(self.K3)
        Fp_K4 = self.F_p(self.K4)
        
        # K1 = ID_MSB || Fp(K4) || Fp(K3)
        term_K1 = (ID_MSB << (2 * quarter_k)) | (Fp_K4 << quarter_k) | Fp_K3

        # K2 = Fp(K1) || Fp(K4) || ID_LSB
        term_K2 = (Fp_K1 << (3 * quarter_k)) | (Fp_K4 << (2 * quarter_k)) | ID_LSB

        # K3 = ID_MSB || Fp(K4) || Fp(K2)
        term_K3 = (ID_MSB << (2 * quarter_k)) | (Fp_K4 << quarter_k) | Fp_K2

        # K4 = Fp(K3) || Fp(K1) || ID_LSB
        term_K4 = (Fp_K3 << (3 * quarter_k)) | (Fp_K1 << (2 * quarter_k)) | ID_LSB
        
        old_IDS = self.IDS
        old_K1 = self.K1
        
        self.IDS = old_IDS ^ n2 ^ old_K1
        self.K1 = old_K1 ^ n2 ^ term_K1
        self.K2 = self.K2 ^ n2 ^ term_K2
        self.K3 = self.K3 ^ n1 ^ term_K3
        self.K4 = self.K4 ^ n1 ^ term_K4

    def verifyID(self, test_ID):
        return 1 if test_ID == self.ID else 0


def attack(oracle):
    """
    Exploit EMAP vulnerability via passive observation (Stage 4 of Li & Deng).
    Recover n1, n2 from message properties, then derive ID from key update equations.
    """
    k = oracle.k
    history = []
    curr_IDS = oracle.IDS
    max_collect_runs = 64
    
    for _ in range(max_collect_runs):
        out, _ = oracle.protocolRun1()
        if out:
            next_IDS = oracle.IDS
            history.append({
                'IDS': curr_IDS,
                'next_IDS': next_IDS,
                'A': out['A'],
                'B': out['B'],
                'D': out['D']
            })
            curr_IDS = next_IDS

            if len(history) > 2:
                recovered = attempt_recovery(history, k)
                if recovered is not None and oracle.verifyID(recovered):
                    return recovered
    
    return attempt_recovery(history, k)

def attempt_recovery(history, k):
    """Recover ID from collected protocol runs using bitwise analysis of messages."""
    computed_data = []
    
    for run in history:
        IDS = run['IDS']
        next_IDS = run['next_IDS']
        A = run['A']
        B = run['B']
        D = run['D']
        
        n1 = 0
        n2 = 0
        
        for bit in range(k):
            ids_bit = (IDS >> bit) & 1
            
            if ids_bit == 0:
                n2_val = (D >> bit) & 1
                n2 |= (n2_val << bit)
                
                a_val = (A >> bit) & 1
                next_ids_val = (next_IDS >> bit) & 1
                n1_val = a_val ^ next_ids_val ^ n2_val
                n1 |= (n1_val << bit)
            else:
                b_val = (B >> bit) & 1
                n1_val = 1 - b_val
                n1 |= (n1_val << bit)
                
                a_val = (A >> bit) & 1
                next_ids_val = (next_IDS >> bit) & 1
                n2_val = a_val ^ next_ids_val ^ n1_val
                n2 |= (n2_val << bit)
        
        K1 = IDS ^ next_IDS ^ n2
        K4_partial = D ^ n2
        
        computed_data.append({
            'n1': n1,
            'n2': n2,
            'K1': K1,
            'K4_partial': K4_partial,
            'IDS': IDS
        })
    
    if len(computed_data) < 2:
        return 0

    # Recover ID_MSB (upper k/2 bits) from K1 update equation
    curr = computed_data[0]
    next_run = computed_data[1]
    
    K1 = curr['K1']
    K1_new = next_run['K1']
    n2 = curr['n2']
    
    term = K1 ^ K1_new ^ n2
    quarter_k = k // 4
    ID_MSB = (term >> (2 * quarter_k)) & ((1 << (k // 2)) - 1)
    
    # Recover ID_LSB (lower k/2 bits) from K4 update equation
    ID_LSB = 0
    ID_LSB_mask = 0
    
    for i in range(len(computed_data) - 1):
        curr = computed_data[i]
        next_run = computed_data[i+1]
        
        IDS = curr['IDS']
        next_IDS = next_run['IDS']
        n1 = curr['n1']
        
        valid_mask = IDS & next_IDS
        
        K4 = curr['K4_partial']
        K4_new = next_run['K4_partial']
        diff = K4 ^ K4_new ^ n1
        
        relevant_mask = valid_mask & ((1 << (k // 2)) - 1)
        new_bits = relevant_mask & (~ID_LSB_mask)
        
        if new_bits:
            ID_LSB |= (diff & new_bits)
            ID_LSB_mask |= new_bits
            
        if ID_LSB_mask == ((1 << (k // 2)) - 1):
            break
            
    if ID_LSB_mask != ((1 << (k // 2)) - 1):
        return None

    full_ID = (ID_MSB << (k // 2)) | ID_LSB
    return full_ID

def attack_runs_single(k=96):
    """Execute attack on single EMAP oracle and return number of runs needed."""
    oracle = EMAPoracle(k=k)
    oracle.run_count = 0
    ID_guess = attack(oracle)
    
    if ID_guess is not None and oracle.verifyID(ID_guess):
        return oracle.run_count
    else:
        return None

def empirical_runs(trials=20, k=96):
    """Estimate average EMAP protocol runs needed."""
    counts = []
    fails = 0
    
    for _ in range(trials):
        r = attack_runs_single(k=k)
        if r is None:
            fails += 1
        else:
            counts.append(r)

    avg_runs = sum(counts) / len(counts) if counts else float('nan')
    print(f"EMAP: avg runs ≈ {avg_runs:.2f} over {trials} trials (k={k}), fails={fails}")
    return avg_runs, counts

def experiment_scaling(k_values, trials=20):
    """Estimate how required runs for EMAP attack scale with k."""
    results = {}

    print("Empirical scaling of EMAP attack (avg runs over trials)")
    print("k (bits)\tavg runs\tmin\tmax\tfails")

    for k in k_values:
        run_counts = []
        fails = 0
        for _ in range(trials):
            r = attack_runs_single(k=k)
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
    return avg_runs, counts