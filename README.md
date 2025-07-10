# RootCrypt and the NERP Problem

**Marshall Ta**  
Version 1.0.1 · July 2025

---

## Abstract

This document introduces and outlines **RootCrypt**, a hybrid post-quantum encryption scheme grounded in a new hardness assumption called **NERP**  
(Nonlinear Entangled Ring Projection). By combining a chaotic, nonlinear ring-based key exchange with AES-256-GCM authenticated encryption,  
RootCrypt offers resistance against both classical and quantum adversaries. We contrast NERP with its lattice-based predecessor NELP and highlight  
how integer-ring arithmetic, enhanced entropy, and modern AEAD mitigate earlier weaknesses.

---

## Table of Contents

- [Introduction](#introduction)  
- [From NELP to NERP](#from-nelp-to-nerp)  
- [Defining the NERP Problem](#defining-the-nerp-problem)  
- [Hybrid Encryption Design](#hybrid-encryption-design)  
  - [KEM: NERP-Based Key Encapsulation](#kem-nerp-based-key-encapsulation)  
  - [DEM: AES-256-GCM](#dem-aes-256-gcm)  
- [Feature Comparison: NELP vs. NERP](#feature-comparison-nelp-vs-nerp)  
- [Comparison with CRYSTALS-Kyber](#comparison-with-crystals-kyber)  
- [Open Questions and Future Work](#open-questions-and-future-work)  
- [Conclusion](#conclusion)  

---

1. ## Introduction

As quantum computing advances, widely used public-key primitives such as RSA and ECC face obsolescence. In mid-2025, NIST selected  
CRYSTALS-Kyber (Module-LWE) for standardization, owing to its solid proofs and efficient implementation. RootCrypt pursues an alternative:  
it embeds secrets into a nonlinear ring map, yielding the NERP challenge. Our goal is to merge cryptographic unpredictability with performance  
by leveraging structured integer rings.

---

2. ## From NELP to NERP

The initial RootCrypt design relied on **NELP** (Nonlinear Entangled Lattice Projection), which used floating-point vectors, fractal mappings,  
and Gaussian perturbations. NELP suffered from:

- Platform-dependent rounding errors and decryption failures  
- Limited seed entropy (64 bits) vulnerable to brute-force  
- No formal reduction to a standard hard problem  
- Lack of side-channel protections  

**NERP** overcomes these by adopting:

- Fixed-width integer rings (e.g., $\mathbb{Z}_{2^{16}}^n$)  
- Platform-independent modular arithmetic  
- 128-bit seed entropy  
- Deterministic nonlinear mappings  
- Native support for AES-256-GCM  

---

3. ## Defining the NERP Problem

Let $f_s: \mathbb{Z}_q^n \to \mathbb{Z}_q^n$ be a nonlinear ring function parameterized by seed $s$. The public key publishes noisy projections:

Let $P_i = f_s(x_i) + \eta_i$ be noisy projections, where $\eta_i$ is small random noise. The challenge is to recover any preimage $x' \approx x_i$
that maps within noise tolerance of $P_i$, without knowledge of $x_i$ or $s$. Security relies on:

1. Intractability of inverting $f_s$  
2. Indistinguishability of $f_s(x) + \eta$ from random over $\mathbb{Z}_q^n$

These assumptions, while plausible, are not yet reducible to a standard problem like LWE or Ring-LWE.

---

4. ## Hybrid Encryption Design

### KEM: NERP-Based Key Encapsulation

1. **KeyGen:** Generate $x \in \mathbb{Z}_q^n$, derive $f_s(x)$, publish $P$
2. **Encapsulation:** Recipient selects the closest projection to a hashed message vector, deriving $f_s(x)$

### DEM: AES-256-GCM

- Apply HKDF to $f_s(x)$ and a salt to derive a 256-bit key.  
- Encrypt the payload with AES-256-GCM using a 128-bit IV and 16-byte authentication tag.  

This composition yields authenticated, quantum-resistant encryption.

---

5. ## Feature Comparison: NELP vs. NERP

| Feature             | NELP (Lattice)          | NERP (Ring)                    |
|---------------------|-------------------------|--------------------------------|
| Arithmetic          | Floating-point (`double`)| Integer mod q (`int32_t mod q`)|
| Stability           | Low (rounding errors)   | High (modular arithmetic)      |
| Noise               | Gaussian                | Discrete                       |
| Decryption Robustness | Fragile inverse map     | Deterministic                  |
| Seed Entropy        | 64 bits                 | 128 bits                       |
| Side-Channel Mitigation | Weak                    | Stronger (constant-time friendly) |
| AE Integration      | AES-CBC                 | AES-256-GCM                    |
| Formal Link         | None                    | Aligned with Ring-LWE concepts |

---

6. ## Comparison with CRYSTALS-Kyber

| Feature               | RootCrypt (NERP)         | CRYSTALS-Kyber (Kyber-768)       |
|-----------------------|--------------------------|----------------------------------|
| Hardness Basis        | Heuristic nonlinear map  | Module-LWE with tight reduction  |
| Public Key Size       | ~8 KiB (configurable)    | 1,184 bytes                      |
| Ciphertext Size       | Message + 64 B overhead  | 1,088 bytes                      |
| Provable Security     | Conjectural              | IND-CCA2 via FO transform        |
| Performance           | Moderate (no NTT)        | Very fast (NTT-accelerated)      |
| Decryption Failure    | None                     | Negligible (~2⁻¹⁶⁴)              |
| AE Scheme             | AES-256-GCM              | Built-in FO transform            |

---

7. ## Open Questions and Future Work

- Formal reduction of NERP to Ring-LWE or a related problem  
- Security analysis of fₛ as a one-way function  
- Behavior under chosen-ciphertext attacks (CCA)  
- Acceleration via NTT or polynomial-ring constructions  

---

8. ## Conclusion

RootCrypt and the NERP assumption chart a fresh direction in post-quantum hybrid encryption. By shifting from floating-point lattices to  
structured integer rings, boosting entropy, and embracing authenticated encryption, NERP overcomes its predecessor’s shortcomings. NERP’s
ring operations are designed for constant-time evaluation, though formal timing leakage analysis remains future work. Though promising, 
it requires rigorous proofs and extensive cryptanalysis before standardization can proceed.

As both RootCrypt and NERP are yet to be more rigorously studied, this whitepaper doesnt completely exempt either of the two technological
advancements from being problem free, and there is a very clear bar to be raised, as I expect within at least the next 20 years to be raised.
With all said, RootCrypt and NERP prove to be two very useful innovations within the cybersecurity landscape, and this opens the door for
a multitude of other tech and security innovations.

---