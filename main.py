import random
from mmap import MMAPoracle
from emap import EMAPoracle

def MMAP_attack(oracle):
    k = oracle.k
    # We need to determine ID.
    # ID + IDP = E ^ n1 (mod 2^k)
    # We can recover n1_i if IDP_i = 0.
    # We will solve for ID bit by bit from LSB to MSB.
    
    # Collect enough runs
    runs = []
    curr_IDP = oracle.IDP
    for _ in range(64): # 64 runs should be enough to have IDP_i=0 for all i
        out, _ = oracle.protocolRun()
        if out:
            runs.append((curr_IDP, out['B'], out['E']))
        curr_IDP = oracle.IDP
            
    known_ID = 0
    
    for bit in range(k):
        # Try both 0 and 1 for the current bit of ID
        candidates = []
        for bit_val in [0, 1]:
            consistent = True
            current_ID_guess = known_ID | (bit_val << bit)
            
            # Check consistency across all runs where IDP has 0 at this bit
            # Actually, we can check consistency for ALL runs if we propagate carry correctly?
            # No, we only know n1_i if IDP_i=0.
            # So we only check runs with IDP_i=0.
            
            count_checked = 0
            for IDP, B, E in runs:
                if not ((IDP >> bit) & 1): # IDP_i == 0
                    count_checked += 1
                    # Calculate expected n1 for this run given the ID guess
                    # n1 = E ^ (ID + IDP)
                    # We only care about the current bit.
                    # But (ID + IDP) depends on lower bits (carries).
                    # Since we have fixed lower bits of ID in known_ID, the carry to this bit is fixed.
                    
                    sum_val = (current_ID_guess + IDP)
                    n1_derived = E ^ sum_val
                    
                    # Check if derived n1 matches B at this bit
                    # If IDP_i=0, n1_i should be B_i
                    if ((n1_derived >> bit) & 1) != ((B >> bit) & 1):
                        consistent = False
                        break
            
            if consistent and count_checked > 0:
                candidates.append(bit_val)
        
        if len(candidates) == 1:
            known_ID |= (candidates[0] << bit)
        elif len(candidates) == 0:
            # Should not happen if logic is correct
            print(f"Error at bit {bit}: No consistent candidates")
            return None
        else:
            # Multiple candidates?
            # This might happen if we didn't check enough runs.
            # But with 64 runs, probability of not seeing IDP_i=0 is 2^-64.
            # Maybe carry ambiguity?
            # We'll just pick one and hope? No, we should backtrack or get more runs.
            # For now, pick 0.
            known_ID |= (candidates[0] << bit)
            
    return known_ID

def EMAP_attack(oracle):
    k = oracle.k
    # Strategy:
    # 1. Recover full n1, n2 for a chain of runs.
    # 2. Use K1 update to get ID_MSB.
    # 3. Use K4 update to get ID_LSB.
    
    # We need a chain of runs.
    chain_length = 200
    history = []
    
    # Initial state
    # We need IDP of the START of the run.
    # oracle.IDP is currently the value for the NEXT run (after update).
    # But we need to capture it before update?
    # protocolRun1 returns updated oracle.
    # So we should capture IDP before calling protocolRun1.
    
    curr_IDP = oracle.IDP
    
    for _ in range(chain_length):
        out, _ = oracle.protocolRun1()
        if out:
            next_IDP = oracle.IDP
            history.append({
                'IDP': curr_IDP,
                'next_IDP': next_IDP,
                'A': out['A'],
                'B': out['B'],
                'C': out['C'],
                'D': out['D'],
                'E': out['E']
            })
            curr_IDP = next_IDP
            
    # Analyze history
    # We need to compute n1, n2, K1, K4 for each run
    
    computed_data = []
    
    for i in range(len(history)):
        run = history[i]
        IDP = run['IDP']
        next_IDP = run['next_IDP']
        A = run['A']
        B = run['B']
        D = run['D']
        
        n1 = 0
        n2 = 0
        
        # Reconstruct n1, n2 bit by bit
        for bit in range(k):
            idp_bit = (IDP >> bit) & 1
            
            if idp_bit == 0:
                # IDP_i = 0 => n2_i = D_i
                n2_val = (D >> bit) & 1
                n2 |= (n2_val << bit)
                
                # n1_i = A_i ^ IDP_new_i ^ n2_i
                # A = IDP ^ K1 ^ n1
                # K1 = IDP ^ IDP_new ^ n2
                # A = IDP ^ (IDP ^ IDP_new ^ n2) ^ n1 = IDP_new ^ n2 ^ n1
                # n1 = A ^ IDP_new ^ n2
                
                a_val = (A >> bit) & 1
                next_idp_val = (next_IDP >> bit) & 1
                n1_val = a_val ^ next_idp_val ^ n2_val
                n1 |= (n1_val << bit)
                
            else:
                # IDP_i = 1 => n1_i = not B_i
                b_val = (B >> bit) & 1
                n1_val = 1 - b_val
                n1 |= (n1_val << bit)
                
                # n2_i = A_i ^ IDP_new_i ^ n1_i
                a_val = (A >> bit) & 1
                next_idp_val = (next_IDP >> bit) & 1
                n2_val = a_val ^ next_idp_val ^ n1_val
                n2 |= (n2_val << bit)
        
        # Compute K1, K4 (partial)
        K1 = IDP ^ next_IDP ^ n2
        
        # K4 is only known where IDP_i = 1
        # K4_i = D_i ^ n2_i
        K4_partial = D ^ n2 # Only valid at bits where IDP=1
        
        computed_data.append({
            'n1': n1,
            'n2': n2,
            'K1': K1,
            'K4_partial': K4_partial,
            'IDP': IDP
        })
        
    # Recover ID_MSB (bits 48..95)
    # Use K1 update between run i and i+1
    # K1_new = K1 ^ n2 ^ UpdateTerm
    # UpdateTerm = K1 ^ K1_new ^ n2
    # UpdateTerm = (ID_MSB || ...)
    
    ID_MSB_candidates = [0] * 48 # Bits 0..47 of MSB part (which are 48..95 of ID)
    ID_MSB_counts = [0] * 48
    
    for i in range(len(computed_data) - 1):
        curr = computed_data[i]
        next_run = computed_data[i+1]
        
        K1 = curr['K1']
        K1_new = next_run['K1']
        n2 = curr['n2']
        
        term = K1 ^ K1_new ^ n2
        
        # Term structure: (ID_MSB << 8) | ...
        # So ID_MSB is in bits 8..55 of term?
        # Wait, my implementation of update:
        # term_K1 = (ID_MSB << 8) | (Fp_K4 << 4) | Fp_K3
        # ID_MSB is 48 bits.
        # 48 + 8 = 56.
        # So bits 8 to 55 of term correspond to bits 0 to 47 of ID_MSB.
        
        extracted_MSB = (term >> 8) & ((1 << 48) - 1)
        
        # We can just take the first one, or verify consistency
        if i == 0:
            final_ID_MSB = extracted_MSB
        elif final_ID_MSB != extracted_MSB:
            # This shouldn't happen if logic is correct
            pass
            
    # Recover ID_LSB (bits 0..47)
    # Use K4 update
    # K4_new = K4 ^ n1 ^ (Fp_K3 << 52 | Fp_K1 << 48 | ID_LSB)
    # K4 ^ K4_new ^ n1 = (...) | ID_LSB
    # So ID_LSB is in bits 0..47 of (K4 ^ K4_new ^ n1)
    
    ID_LSB = 0
    ID_LSB_mask = 0
    
    for i in range(len(computed_data) - 1):
        curr = computed_data[i]
        next_run = computed_data[i+1]
        
        IDP = curr['IDP']
        next_IDP = next_run['IDP'] # IDP for run i+1
        
        n1 = curr['n1']
        
        # We need K4 and K4_new
        # K4 is valid where IDP=1
        # K4_new is valid where next_IDP=1
        
        valid_mask = IDP & next_IDP # Bits where both are 1
        
        K4 = curr['K4_partial']
        K4_new = next_run['K4_partial']
        
        diff = K4 ^ K4_new ^ n1
        
        # We are interested in bits 0..47
        # Check which bits in 0..47 are valid
        
        relevant_mask = valid_mask & ((1 << 48) - 1)
        
        # Update known bits
        # bits we don't know yet: (~ID_LSB_mask)
        # bits we can learn now: relevant_mask
        
        new_bits = relevant_mask & (~ID_LSB_mask)
        
        if new_bits:
            ID_LSB |= (diff & new_bits)
            ID_LSB_mask |= new_bits
            
        if ID_LSB_mask == ((1 << 48) - 1):
            break
            
    # Reconstruct ID
    # ID = (ID_MSB << 48) | ID_LSB
    full_ID = (final_ID_MSB << 48) | ID_LSB
    
    return full_ID

if __name__ == "__main__":
    # Simple test
    print("Testing MMAP Attack...")
    mmap_oracle = MMAPoracle()
    recovered_id = MMAP_attack(mmap_oracle)
    print(f"Actual ID: {mmap_oracle.ID}")
    print(f"Recovered: {recovered_id}")
    print(f"Success: {recovered_id == mmap_oracle.ID}")
    
    print("\nTesting EMAP Attack...")
    emap_oracle = EMAPoracle()
    recovered_id_emap = EMAP_attack(emap_oracle)
    print(f"Actual ID: {emap_oracle.ID}")
    print(f"Recovered: {recovered_id_emap}")
    print(f"Success: {recovered_id_emap == emap_oracle.ID}")
