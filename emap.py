import random

class EMAPoracle:
    def __init__(self, k=96):
        self.k = k
        self.MOD = 2 ** k
        self.MASK = self.MOD - 1
        # ⬇️ NEW: count how many protocol runs this oracle has seen
        self.run_count = 0
        
        # Initialize secrets
        self.ID = random.getrandbits(k)
        self.IDP = random.getrandbits(k)
        self.K1 = random.getrandbits(k)
        self.K2 = random.getrandbits(k)
        self.K3 = random.getrandbits(k)
        self.K4 = random.getrandbits(k)

    def F_p(self, z):
        # Divide z into 4-bit blocks and XOR them
        # z is k bits.
        res = 0
        temp_z = z
        # We process 4 bits at a time.
        # Since k is multiple of 4 (96), we can just loop.
        # We need to handle the bits carefully.
        # The example: 1011 0110 1000 -> 1011 ^ 0110 ^ 1000
        # This is equivalent to (z >> 0) ^ (z >> 4) ^ (z >> 8) ... & 0xF
        
        # Number of 4-bit blocks
        num_blocks = self.k // 4
        for i in range(num_blocks):
            block = (z >> (i * 4)) & 0xF
            res ^= block
        return res

    def protocolRun1(self):
        # ⬇️ NEW
        self.run_count += 1
        # Reader Step 3
        n1 = random.getrandbits(self.k)
        n2 = random.getrandbits(self.k)
        
        A = self.IDP ^ self.K1 ^ n1
        B = (self.IDP | self.K2) ^ n1
        C = self.IDP ^ self.K3 ^ n2
        
        # Tag Step 4
        n1_prime = A ^ self.IDP ^ self.K1
        n2_prime = C ^ self.IDP ^ self.K3
        
        B_check = (self.IDP | self.K2) ^ n1_prime
        
        if B != B_check:
            return None, self
            
        # Tag Step 5
        D = (self.IDP & self.K4) ^ n2_prime
        
        # E = (IDP & n1 v n2) ^ ID ^ K1 ^ K2 ^ K3 ^ K4
        # Operator precedence: & is higher than ^, but v (OR) is usually lower than &.
        # Spec: (IDP ^ n1 v n2). Wait.
        # Spec text: (IDP \wedge n1 \vee n2)
        # AND has higher precedence than OR usually.
        # So (IDP & n1) | n2.
        # Let's check standard math notation precedence. AND usually binds tighter than OR.
        # Python: & binds tighter than |.
        term1 = (self.IDP & n1_prime) | n2_prime
        E = term1 ^ self.ID ^ self.K1 ^ self.K2 ^ self.K3 ^ self.K4
        
        # Update keys
        self._update_keys(n1_prime, n2_prime)
        
        outStruct = {
            'A': A,
            'B': B,
            'C': C,
            'D': D,
            'E': E
        }
        
        return outStruct, self

    def impersonate_reader(self, A, B, C):
        # Tag Step 4
        n1_prime = A ^ self.IDP ^ self.K1
        n2_prime = C ^ self.IDP ^ self.K3
        
        B_check = (self.IDP | self.K2) ^ n1_prime
        
        if B != B_check:
            return None, None, self
            
        # Tag Step 5
        D = (self.IDP & self.K4) ^ n2_prime
        term1 = (self.IDP & n1_prime) | n2_prime
        E = term1 ^ self.ID ^ self.K1 ^ self.K2 ^ self.K3 ^ self.K4
        
        # Update keys
        self._update_keys(n1_prime, n2_prime)
        
        return D, E, self

    def _update_keys(self, n1, n2):
        old_IDP = self.IDP
        old_K1 = self.K1
        old_K2 = self.K2
        old_K3 = self.K3
        old_K4 = self.K4
        
        # ID split
        # ID_1_48: 48 most significant bits.
        # ID_49_96: 48 least significant bits.
        half_k = self.k // 2
        ID_MSB = (self.ID >> half_k) & ((1 << half_k) - 1)
        ID_LSB = self.ID & ((1 << half_k) - 1)
        
        Fp_K1 = self.F_p(old_K1)
        Fp_K2 = self.F_p(old_K2)
        Fp_K3 = self.F_p(old_K3)
        Fp_K4 = self.F_p(old_K4)
        
        # Construct the update terms
        # Term for K1: (ID_MSB || Fp(K4) || Fp(K3))
        # ID_MSB is 48 bits. Fp is 4 bits.
        # Structure: 48 bits | 4 bits | 4 bits = 56 bits?
        # Wait, K is 96 bits.
        # The concatenation must result in 96 bits? Or is it just XORed?
        # Spec: K1_new = K1 ^ n2 ^ ( ... )
        # If the term in parens is not 96 bits, how does it work?
        # Maybe the concatenation is padded or aligned?
        # Let's look at the sizes.
        # ID_MSB: 48 bits.
        # Fp: 4 bits.
        # Total: 48 + 4 + 4 = 56 bits.
        # 96 - 56 = 40 bits missing?
        # Maybe I misunderstood Fp or the split.
        # "Dividing the bit string z ... into 4-bit blocks"
        # "XORing the four bits in each block" -> Result is 4 bits.
        # Maybe the concatenation implies something else.
        # Let's re-read carefully.
        # "ID_1:48 || Fp(K4) || Fp(K3)"
        # Maybe Fp returns something larger?
        # No, example: 1011... -> 101. 3 bits? No, 4 bits.
        
        # Let's check if Fp is applied to each block and we get a string of 4-bit results?
        # "XORing the four bits in each block"
        # "Example: If x=1011 0110 1000, then Fp(x)=101"
        # 101 is 5.
        # 1011 ^ 0110 ^ 1000 = 1101 ^ 1000 = 0101 = 5.
        # So Fp returns a single 4-bit value.
        
        # If the update term is small, it just XORs with the lower bits?
        # Or is it aligned?
        # Usually in these protocols, lengths match.
        # Maybe ID split is different?
        # "ID_1:48 are the 48 most significant bits"
        # Maybe the concatenation fills the 96 bits?
        # 48 + 4 + 4 = 56.
        # This is strange.
        # Let's check if there's a typo in my understanding of Fp.
        # Maybe Fp returns a 48-bit value? No.
        
        # Let's look at the update equations again.
        # K1 = K1 ^ n2 ^ (ID_MSB || Fp(K4) || Fp(K3))
        # Maybe || means XOR? No, usually concatenation.
        # Maybe the Fp values are expanded?
        # Or maybe the ID parts are larger?
        # If k=96.
        # Maybe the term is just 56 bits and we XOR it with the LSB of K1?
        # Or MSB?
        # I will assume it's aligned to LSB.
        # Construct the term: (ID_MSB << 8) | (Fp_K4 << 4) | Fp_K3
        
        term_K1 = (ID_MSB << 8) | (Fp_K4 << 4) | Fp_K3
        term_K2 = (Fp_K1 << 52) | (Fp_K4 << 48) | ID_LSB # 4 + 4 + 48 = 56
        term_K3 = (ID_MSB << 8) | (Fp_K4 << 4) | Fp_K2
        term_K4 = (Fp_K3 << 52) | (Fp_K1 << 48) | ID_LSB
        
        self.IDP = old_IDP ^ n2 ^ old_K1
        self.K1 = old_K1 ^ n2 ^ term_K1
        self.K2 = old_K2 ^ n2 ^ term_K2
        self.K3 = old_K3 ^ n1 ^ term_K3
        self.K4 = old_K4 ^ n1 ^ term_K4

    def verifyID(self, test_ID):
        return 1 if test_ID == self.ID else 0
