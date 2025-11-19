import random

class MMAPoracle:
    def __init__(self, k=96):
        self.k = k
        self.MOD = 2 ** k
        self.MASK = self.MOD - 1
        
        # Initialize secrets
        self.ID = random.getrandbits(k)
        self.IDP = random.getrandbits(k)
        self.K1 = random.getrandbits(k)
        self.K2 = random.getrandbits(k)
        self.K3 = random.getrandbits(k)
        self.K4 = random.getrandbits(k)

    def protocolRun(self):
        # Reader Step 3
        n1 = random.getrandbits(self.k)
        n2 = random.getrandbits(self.k)
        
        A = self.IDP ^ self.K1 ^ n1
        B = (self.IDP & self.K2) | n1
        C = (self.IDP + self.K3 + n2) & self.MASK
        
        # Tag Step 4
        n1_prime = A ^ self.IDP ^ self.K1
        n2_prime = (C - self.IDP - self.K3) & self.MASK
        
        B_check = (self.IDP & self.K2) | n1_prime
        
        if B != B_check:
            return None, self
            
        # Tag Step 5
        D = (self.IDP | self.K4) & n2_prime
        E = ((self.ID + self.IDP) & self.MASK) ^ n1_prime
        
        # Reader Step 6 (Implicitly checking if we can recover ID, but here we just update)
        # In a real scenario, Reader would verify ID. Here we assume successful run updates keys.
        
        # Step 7: Update
        # Note: The spec implies both update using the shared values n1, n2.
        # Since n1_prime == n1 and n2_prime == n2 if auth succeeds.
        
        old_IDP = self.IDP
        old_K1 = self.K1
        old_K2 = self.K2
        old_K3 = self.K3
        old_K4 = self.K4
        
        self.IDP = ((old_IDP + (n1 ^ n2)) & self.MASK) ^ self.ID
        self.K1 = old_K1 ^ n2 ^ ((old_K3 + self.ID) & self.MASK)
        self.K2 = old_K2 ^ n2 ^ ((old_K4 + self.ID) & self.MASK)
        self.K3 = ((old_K3 ^ n1) + (old_K1 ^ self.ID)) & self.MASK
        self.K4 = ((old_K4 ^ n1) + (old_K2 ^ self.ID)) & self.MASK
        
        outStruct = {
            'A': A,
            'B': B,
            'C': C,
            'D': D,
            'E': E
        }
        
        return outStruct, self

    def verifyID(self, test_ID):
        return 1 if test_ID == self.ID else 0
