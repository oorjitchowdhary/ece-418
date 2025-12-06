# ECE 418 Course Project: Security Analysis of RFID Authentication Protocols
Network Security & Cryptography, UW Fall 2025

**Collaborators:** Oorjit Chowdhary, Aakash Namboodiri

## Overview

This project implements and analyzes security vulnerabilities in two RFID mutual authentication protocols: MMAP (M²AP) and EMAP, as described in the paper by Li and Deng [4]. We implement passive eavesdropping attacks that recover the secret tag identifier (ID) by observing protocol runs between legitimate tags and readers.

## Implementation

### Protocol Oracles

- **`MMAPoracle`**: Implements the M²AP protocol with tag initialization, protocol execution (`protocolRun`), and key updates
- **`EMAPoracle`**: Implements the EMAP protocol with enhanced security features including parity function `F_p` and more complex key update mechanisms

### Attack Functions

- **`mmap.attack()`**: Exploits the vulnerability where message B reveals nonce bits when `(IDP)_i = 0`, enabling bit-by-bit ID recovery
- **`emap.attack()`**: Exploits bitwise properties of messages A, B, D to recover nonces n1, n2, then derives ID from key update equations

Both attacks successfully recover the complete secret ID through passive observation alone.

## Experimental Results

### Question 1: Scaling Analysis

**How does the number of required protocol runs scale with key length k for each attack?**

Our empirical experiments tested both protocols at k = 32, 64, 96, and 128 bits over 20 trials each:

| Key Length k (bits) | MMAP Avg Runs | EMAP Avg Runs |
|---------------------|---------------|---------------|
| 32                  | 6.60          | 19.05         |
| 64                  | 7.60          | 19.25         |
| 96                  | 7.95          | 22.60         |
| 128                 | 8.55          | 23.25         |

**Analysis:**

1. **MMAP Scaling**: The attack scales extremely slowly, growing from ~6.6 runs at k=32 to only ~8.6 runs at k=128. This near-logarithmic scaling indicates the attack complexity is approximately O(log k), making it highly efficient even for large key lengths.

2. **EMAP Scaling**: The attack also scales slowly but requires significantly more runs overall. Starting at ~19 runs for k=32 and reaching ~23 runs at k=128, the scaling is similarly logarithmic but with a higher constant factor.

3. **Comparative Security**: While EMAP requires roughly 2.5-3× more protocol runs than MMAP across all key lengths, both protocols are fundamentally **insecure** against passive eavesdropping. The difference in run counts is practically insignificant—an adversary can compromise either system after observing fewer than 25 authentication sessions even at k=128 bits.

**Security Implications:**

Neither protocol provides adequate security against passive attacks. The logarithmic scaling means that even doubling or quadrupling the key length adds only a handful of additional runs to the attack requirements. For reference, a secure protocol should require exponential effort (2^k operations) as k increases; here we see only logarithmic growth, representing a catastrophic security failure.

**Plot Analysis:**

The attached plot clearly shows:
- MMAP (blue line): Shallow, near-linear growth from ~6.5 to ~8.5 runs
- EMAP (orange line): Similar shallow growth from ~19 to ~23 runs, with slightly more variability at k=96
- Both curves are nearly flat compared to the ideal exponential security requirement

### Question 2: Progressive Information Leakage

**After observing ℓ protocol runs, what fraction of ID is revealed?**

#### (a) MMAP Information Leakage

In MMAP, the attack exploits message B when `(IDP)_i = 0` to reveal `(n1)_i = (B)_i`. Since IDP evolves after each run with its bits appearing pseudo-randomly:

- **Probability that bit i is revealed in one run**: P((IDP)_i = 0) = 0.5
- **After ℓ runs, probability bit i remains hidden**: (0.5)^ℓ
- **Expected fraction of ID bits recovered**: 1 - (0.5)^ℓ

| Runs ℓ | Fraction Recovered |
|--------|-------------------|
| 1      | 50%               |
| 2      | 75%               |
| 4      | 93.75%            |
| 8      | 99.61%            |
| 10     | 99.90%            |

The attack recovers ID **bit-by-bit** through the relationship `E = (ID + IDP) ⊕ n1`. Once sufficient bits of n1 are known from observing B when IDP bits are 0, the adversary can solve for ID bits sequentially, handling carry propagation in the addition operation.

**Key length dependence**: The fraction depends primarily on ℓ, not k. However, larger k requires slightly more runs to ensure all bits are observed (statistical coverage), explaining the mild logarithmic growth in our experiments.

#### (b) EMAP Information Leakage

EMAP's attack is more complex, recovering ID through key update equations:

1. **Nonce recovery**: Each run reveals n1 and n2 through bitwise analysis:
   - When `(IDS)_i = 0`: message D directly reveals `(n2)_i`
   - When `(IDS)_i = 1`: message B reveals `(n1)_i = ¬(B)_i`

2. **ID_MSB recovery**: Requires only 2 runs to extract the upper k/2 bits from the K1 update equation

3. **ID_LSB recovery**: Probabilistically accumulates the lower k/2 bits from K4 updates, but only when `(IDS)_i = 1` in consecutive runs

**Information leakage pattern**:
- **First 2 runs**: ~50% of ID recovered (entire MSB half)
- **Runs 3-20**: Progressive LSB recovery, with each run potentially revealing additional LSB bits where IDS bits are 1 in consecutive states
- **Full recovery**: Typically achieved in 15-25 runs depending on k

The key difference from MMAP is that EMAP reveals ID in **two halves** (MSB quickly, LSB probabilistically) rather than uniformly across all bits. This explains why EMAP requires more runs—the LSB recovery is bottlenecked by the need for overlapping IDS = 1 patterns across consecutive runs.

### Question 3: Section 3.1 vs Section 3.2 Attacks

**Section 3.1 Attack (Active Impersonation)**

**Goals**: Enable an adversary to impersonate a legitimate tag to a reader, or vice versa, after observing protocol runs.

**Security Concern**: This is a critical vulnerability because it allows:
- **Tag cloning**: An attacker can create a counterfeit tag that readers will accept as genuine
- **Reader impersonation**: An attacker can masquerade as a legitimate reader to extract information from tags
- **Unauthorized access**: In applications like access control, payment systems, or supply chain management, this enables complete system compromise

**Attack mechanism**: By observing messages (A, B, C) from a legitimate protocol run, an adversary can compute the nonces n1 and n2, then generate valid responses (D, E) that pass authentication checks. This works because:
- The protocols rely on shared secrets (ID, keys) that can be derived from observed messages
- Once the attacker knows the current state (IDS/IDP and keys), they can simulate either party

**Section 3.2 Attack (Full ID Recovery - This Project)**

**Goals**: Completely recover the secret identifier ID through passive eavesdropping.

**Security Concern**: This represents a **complete cryptographic break**:
- The adversary gains permanent knowledge of the tag's identity
- All future and past communications can be traced to the same tag
- The tag can be tracked across different locations/readers
- The recovered ID can be used to create perfect clones

**Attack mechanism**: By observing multiple protocol runs and analyzing the mathematical relationships in message construction and key updates, the adversary reconstructs the entire ID bit-by-bit (MMAP) or in segments (EMAP).

**Key Differences**:

| Aspect | Section 3.1 (Impersonation) | Section 3.2 (ID Recovery) |
|--------|----------------------------|---------------------------|
| **Knowledge gained** | Current session state | Permanent secret ID |
| **Observations needed** | Single protocol run | Multiple runs (8-25) |
| **Attack type** | Active (must participate) | Passive (eavesdrop only) |
| **Temporal scope** | Temporary (one session) | Permanent (all sessions) |
| **Severity** | High (immediate threat) | Critical (complete break) |

Section 3.2 is more severe because recovering ID provides lasting capabilities, while Section 3.1 only works for immediate impersonation. However, Section 3.1 can be executed faster (single observation), making it a more immediate practical threat in real-time attack scenarios.

### Question 4: Removing IDP Dependency

**Vulnerability Analysis**

Both protocols broadcast IDP (MMAP) or IDS (EMAP) in cleartext, enabling:
- Tag tracking across readers (privacy violation)
- Statistical analysis of protocol messages
- Correlation attacks linking multiple sessions
- The cryptographic attacks implemented in this project

**Proposed Modifications**

#### (a) MMAP without IDP

**Modification**: Replace IDP with a hash-based challenge-response:

```
Reader → Tag: n1, n2 (random nonces)
Tag → Reader: A, B, C, D, E computed using only ID, keys, and received nonces
```

Specifically:
- **Remove**: All broadcasts and updates of IDP
- **A** = K1 ⊕ n1 (no IDP)
- **B** = (ID & K2) | n1 (use ID directly, secured by OR)
- **C** = (ID + K3 + n2) mod 2^k
- **D** = (ID | K4) & n2
- **E** = H(ID || K1 || K2 || K3 || K4 || n1 || n2) (cryptographic hash for authentication)

**Security Impact**: 
✓ **Improved**: Removes the primary attack vector (IDP bit observation)
✓ **Privacy**: Tag identity not revealed in cleartext
✗ **Vulnerability remains**: Message B still potentially leaks information through the bitwise operations if analyzed across multiple sessions with the same ID

**Performance Impact**:
- **Computation**: Similar (removes one XOR, potentially adds hash computation for E)
- **Message complexity**: Unchanged (same 5 messages)
- **Storage**: Reduced (no need to store IDP)

#### (b) EMAP without IDS

**Modification**: Eliminate IDS broadcast and use authenticated encryption:

```
Reader → Tag: n1
Tag: Generate n2 internally
Tag → Reader: A = AE_K1(IDS), B = AE_K2(n1, n2), C = MAC(ID || keys || nonces)
```

Where AE denotes authenticated encryption (e.g., AES-GCM) with keys derived from K1, K2, etc.

More practically, keep the structure but encrypt the identifier:
- **IDS transmission**: Send Encrypt_K1(IDS) instead of bare IDS
- **Message computation**: Internal computations use the real IDS, but messages are encrypted
- **Verification**: Reader decrypts with shared keys to verify

**Security Impact**:
✓ **Significantly improved**: Breaks the passive observation attack completely
✓ **Privacy**: IDS cannot be read by eavesdroppers
✓ **Protection**: Prevents both the Section 3.1 and 3.2 attacks as implemented
⚠ **Note**: Still requires secure key management and protection against other attack vectors (timing, power analysis, etc.)

**Performance Impact**:
- **Computation**: Moderate increase (encryption/decryption operations per message)
- **Message size**: Potentially larger (encryption padding, authentication tags)
- **Latency**: Slightly increased (crypto operations)
- **Power consumption**: Higher (important for passive RFID tags)

**Recommended Approach**

For resource-constrained RFID tags, a lightweight approach:
1. **Eliminate cleartext identifiers** completely
2. **Use symmetric challenge-response** with cryptographic MACs
3. **Implement proper nonce handling** to prevent replay attacks
4. **Add mutual authentication** beyond just mathematical operations
5. **Consider standard protocols** like ISO/IEC 9798 or proven RFID authentication schemes

The fundamental issue is that both MMAP and EMAP rely on algebraic operations (XOR, AND, OR, addition) that preserve structure, allowing mathematical attacks. Modern protocols should use cryptographic primitives (AES, SHA) that provide provable security properties.

## Conclusion

Our analysis demonstrates that both MMAP and EMAP are **fundamentally insecure** against passive eavesdropping attacks:

1. Both protocols leak the secret ID after observing fewer than 25 authentication sessions
2. The attack complexity scales logarithmically (not exponentially) with key length
3. The root cause is the combination of cleartext identifier transmission and structured algebraic operations
4. Simple modifications to remove IDP/IDS dependencies improve but don't fully solve the security issues

For production RFID systems, we recommend using established, peer-reviewed authentication protocols with provable security properties rather than custom algebraic schemes.

## References

[4] T. Li and R.H. Deng, "Vulnerability Analysis of EMAP-An Efficient RFID Mutual Authentication Protocol," International Conference on Availability, Reliability and Security, 2007.
