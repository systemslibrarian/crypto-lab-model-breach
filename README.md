# crypto-lab-model-breach

*When the Contract Breaks.*

## What It Is

A live case study in the most important and most misunderstood idea in
applied cryptography: security claims are contracts, and the threat model
is the fine print.

HiAE (ePrint 2025/377) is a real AEAD scheme achieving 340 Gbps on x86
and 180 Gbps on ARM — the fastest cross-platform AEAD ever published.
It claims 256-bit security against key-recovery attacks in the
nonce-respecting setting. That claim is correct.

This demo uses the algebraic attack from ePrint 2025/1203 (Hu et al.,
June 2025 — https://eprint.iacr.org/2025/1203.pdf) as a live illustration
of what happens when an adversary operates outside the assumed boundaries:
under a stronger model where the attacker can submit unlimited forgeries
to the decryption oracle, security falls to 2^209. The HiAE designers
responded in ePrint 2025/1235, maintaining their claims are intact under
the original model. Both positions are correct — which is exactly the point.

Implements real AESL (one AES round, zero round key), a structurally correct
toy-scale HiAE, and simulates all three attack phases with line-by-line output
and full-scale complexity annotations. No backends. No simulated math.

## When to Use It

- You need to teach the difference between a security claim and absolute safety.
- You are evaluating an AEAD for a deployment and need to reason about your actual adversary model, not just the scheme's stated security level.
- You want to understand why "no known attack" always has an asterisk.
- You are building systems that expose decryption as a service and need to understand the implications.
- Do NOT treat this as production code or a definitive verdict on HiAE — it is a teaching demo running toy-scale parameters to illustrate a threat-model argument.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-model-breach](https://systemslibrarian.github.io/crypto-lab-model-breach/)**

The demo implements real AESL (one AES round with a zero round key) and a structurally correct toy-scale HiAE, then walks through all three phases of the extended-oracle algebraic attack with line-by-line output and full-scale complexity annotations. You can watch the attack succeed under the stronger decryption-oracle model and see why the same scheme remains secure under its original nonce-respecting claim — making the role of the threat model concrete rather than abstract.

## What Can Go Wrong

- **The threat model mismatch:** This attack requires both an encryption oracle
  AND a decryption oracle that accepts 2^128 forgery attempts. If your deployment
  cannot expose a decryption oracle to adversaries, you are in the standard model
  and HiAE's 256-bit claim holds.
- **Toy scale vs full scale:** The demo runs on 4-block reduced HiAE with ~2^8
  search spaces. Full attack: 2^130 data, 2^209 time. Not browser-runnable.
  The algebraic structure is identical — only the scale differs.
- **The concurrent paper:** Bille & Tischhauser (ePrint 2025/1180) independently
  reached the same conclusions simultaneously. This is not a solo discovery —
  it reflects a known gap in this family of AEADs.

## Real-World Usage

- The same extended-oracle attack framework was applied to AEGIS first, then Rocca, now HiAE — the pattern suggests any AES-round-function-based AEAD with insufficient key mixing at initialization/finalization may share this structural property.
- If you are designing a new AEAD, your security analysis should explicitly address the extended decryption oracle model even if you choose to exclude it from your formal claims.
- HiAE itself is the IETF CFRG draft draft-pham-cfrg-hiae; deployment decisions should account for whether the target environment (e.g. 6G or GPU/NPU interconnect) can expose decryption oracles to adversaries capable of 2^128 queries.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-model-breach
cd crypto-lab-model-breach
npm install
npm run dev
```

## Related Demos

- [crypto-lab-nonce-guard](https://systemslibrarian.github.io/crypto-lab-nonce-guard/) — how AEAD guarantees collapse outside their nonce assumptions.
- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — AES modes and authenticated encryption fundamentals.
- [crypto-lab-ascon](https://systemslibrarian.github.io/crypto-lab-ascon/) — a standardized lightweight AEAD for comparison.
- [crypto-lab-aegis-gate](https://systemslibrarian.github.io/crypto-lab-aegis-gate/) — AEGIS, the AES-round-function AEAD this attack family first targeted.
- [crypto-lab-protocol-compose](https://systemslibrarian.github.io/crypto-lab-protocol-compose/) — how composition and threat-model choices break real protocols.

## Stack

Vite + TypeScript strict + vanilla CSS. GitHub Pages. No backends.
No external crypto libraries. WebCrypto API only for all primitives.

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
