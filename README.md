# MixBuy: Unlinkable Contingent Payment via Verifiable Witness Encryption

A Python implementation of the **MixBuy** protocol — an oracle-based conditional payment scheme that achieves unlinkability without smart contracts or on-chain transaction logic.

> **Paper:** *MixBuy: Unlinkable Contingent Payment: Implementation of the Attestation Puzzle via Verifiable Witness Encryption*  
> **Authors:** Zahra Tanha & Maksym Voloshyn — University of Luxembourg, MICS (January 2026)

---

## Overview

MixBuy enables a buyer to conditionally purchase a digital product from a seller, where payment is only released if a trusted notary (oracle) attests to a specific event. The key properties are:

- **Fairness** — neither party can cheat: the buyer only pays if they get the product, the seller only releases the product if they receive payment.
- **Unlinkability** — the payment is routed through a mixer so it cannot be linked to the buyer.
- **No smart contracts** — the entire protocol runs on classical cryptographic primitives.

---

## Cryptographic Components

### 1. BLS Signatures over BN128 (`DSc`)
Standard BLS signature scheme using the BN128 pairing-friendly elliptic curve.

- Public keys live in **G1**, signatures in **G2**
- `keygen()` → `(sk̂, v̂k)` where `v̂k = g₀^sk̂`
- `sign(sk, m)` → `σ̂ = sk̂ · H₀(m)` (hash-to-G2 then scalar multiply)
- `verify(vk, m, σ̂)` → checks `e(g₀, σ̂) = e(v̂k, H₀(m))`

### 2. Witness Encryption based on BLS Signatures (`WES` — Figure 3)
Encrypts a plaintext `m` under a *statement* `(v̂k, m̂)` so that it can only be decrypted by anyone holding a valid BLS signature `σ̂` on `m̂` under `v̂k`.

```
Enc((v̂k, m̂), m):
  r₁ ← ℤq,  r₂ ← G_T
  c₁ = g₀^r₁
  c₂ = e(v̂k, H₀(m̂))^r₁ · r₂
  c₃ = H₁(r₂) ⊕ m
  return (c₁, c₂, c₃)

Dec(σ̂, (c₁, c₂, c₃)):
  r₂ = c₂ · e(c₁, σ̂)⁻¹
  return H₁(r₂) ⊕ c₃
```

### 3. Verifiable Witness Encryption for a Relation (`VWER` — Figure 30)
Extends WES with a **cut-and-choose** proof of correctness using γ = 128 rounds, so a buyer can verify the ciphertext is well-formed *before* the oracle's signature is available.

The relation: `R = { (X, w) | X = g^w }`

```
EncR((v̂k, m̂), w):          # Encrypt witness w
  for i in [1..γ]:
    rᵢ ← ℤq;  Rᵢ = g^rᵢ
    cᵢ = WES.Enc((v̂k, m̂), rᵢ)
  (b₁..bᵧ) = H(c₁,R₁,...,cᵧ,Rᵧ)   # Fiat–Shamir challenge
  for i: if bᵢ=1 → open (i, rᵢ); if bᵢ=0 → s_i = rᵢ+w, keep cᵢ
  return ciphertext, proof

VfEncR(c, π, (v̂k, m̂), X):  # Buyer verifies before paying
  check g^sᵢ = Rᵢ · X  for all unopened rounds

DecR(σ̂, c, π):             # Buyer decrypts after oracle attests
  rᵢ = WES.Dec(σ̂, cᵢ)  for each unopened round
  w* = sᵢ - rᵢ
```

### 4. O-UCP Protocol (`Figure 10`)

| Step | Party | Action |
|------|-------|--------|
| `NGen` | Notary | Generates BLS key pair `(v̂k, sk̂)` |
| `SSet4` | Seller | `(c₄, π₄) ← VWER.EncR((v̂k, m_B), pdk)` |
| `BVfSet` | Buyer | `VWER.VfEncR(c₄, π₄, (v̂k, m_B), pek)` → verify before paying |
| `NAttest` | Notary | `τ ← BLS.Sign(sk̂, m_B)` after observing on-chain transaction |
| `BSolve` | Buyer | `pdk ← VWER.DecR(τ, c₄, π₄)` → recover product key |

---

## Repository Structure

```
MixBuy/
├── VWER_BLS_with_block_timing.ipynb  # Main implementation (all code + timing)
├── final.tex                          # LaTeX source of the research paper
├── MixBuy_final.pptx                  # Presentation slides
├── report.pdf                         # Full PDF report
├── requirements.txt                   # Python dependencies
└── README.md
```

---

## Installation

```bash
pip install py-ecc
```

Or from the requirements file:

```bash
pip install -r requirements.txt
```

**Requirements:** Python 3.8+, `py-ecc` (BN128 pairing operations)

---

## Usage

Open and run `VWER_BLS_with_block_timing.ipynb` in Jupyter. The notebook is structured into 7 cells:

1. **Cell 1** — Install dependencies, import `py_ecc.bn128`
2. **Cell 2** — Utility functions: `hash_to_G2`, `hash_to_bytes`, `xor_bytes`
3. **Cell 3** — BLS signature scheme (`BLSSignature` class)
4. **Cell 4** — WES encryption/decryption (`WES_Enc`, `WES_Dec`)
5. **Cell 5** — Diagnostic and test functions
6. **Cell 6** — VWER implementation (`VWER` class with `EncR`, `VfEncR`, `DecR`)
7. **Cell 7** — Complete MixBuy protocol end-to-end demo

Run all cells sequentially. The full protocol test (Cell 7) takes ~15 minutes due to 128 BN128 pairings in the cut-and-choose phase.

---

## Performance (BN128, pure Python `py-ecc`)

| Operation | Time |
|-----------|------|
| Single pairing `e(G2, G1)` | ~6.3 s |
| BLS sign + verify | ~9.5 s |
| `WES_Enc` | ~4.5 s |
| `WES_Dec` | ~4.1 s |
| `VWER.EncR` (γ=128) | ~620 s |
| `VWER.VfEncR` (γ=128) | ~20 ms |
| `VWER.DecR` (~61 rounds) | ~261 s |

> Performance bottleneck is the BN128 Tate pairing computed in pure Python. A native extension (e.g., `blspy` or a Rust binding) would reduce this by 100×+.

---

## Security

- **WES security** reduces to the hardness of the BLS assumption over BN128 (~128-bit security).
- **VWER soundness** holds via the cut-and-choose argument with γ=128 rounds: cheating probability ≤ 2⁻¹²⁸.
- **Hash functions** use SHA-256 / SHAKE-256 modeled as random oracles.

---

## Citation

If you use this code in your research, please cite:

```bibtex
@misc{tanha2026mixbuy,
  title  = {MixBuy: Unlinkable Contingent Payment via Verifiable Witness Encryption},
  author = {Tanha, Zahra and Voloshyn, Maksym},
  year   = {2026},
  note   = {University of Luxembourg, MICS}
}
```

---

## License

This project is released for academic and research purposes.
