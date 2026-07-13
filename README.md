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

Implements real AESL (one AES round, zero round key, verified against the
FIPS-197 round vector), a structurally correct toy-scale HiAE, and a live
key-recovery attack that is **genuinely computed from oracle output**:

1. **Observe** — one encryption-oracle query leaks the keystream block
   `AESL(S0 ⊕ S2)` of the target's post-init state (`ct ⊕ pt`).
2. **Guess-and-determine** — the attack searches an *honestly disclosed reduced
   toy keyspace* (a public function of a 16-bit seed) for the one key whose
   derived keystream reproduces what was observed.
3. **Forge** — it builds a ciphertext+tag with the recovered key and confirms
   the **decryption oracle accepts it** (and rejects a random-tag forgery).

The recovered key is checked byte-for-byte against the instance and is never
read from oracle metadata. **The reduced keyspace is the toy** — recovering a
full random 256-bit HiAE key is the 2^209-time / 2^130-data result of ePrint
2025/1203, which is annotated, never executed in-browser. The AESL differential
math the paper uses (Theorem 1 candidate enumeration, the MITM key equation)
ships as separately unit-tested library functions. No backends, no mocks, no
recordings.

The recovery is shown as what it actually is — an **algebraic equation check**,
not a brute-force count. The captured keystream `A(S0 ⊕ S2)` is treated as a
constraint: candidate keys are re-derived live and lit up **byte-by-byte** where
they satisfy the equation, so wrong keys visibly fail on mismatched bytes and the
recovered key satisfies all sixteen. A companion panel isolates *why the oracle
matters* — the same candidate is unconfirmable in the ciphertext-only world and
confirmed by a real decryption-oracle **accept** in the extended world — and a
closing accept/reject contrast shows the forgery going through as the concrete
meaning of "the contract broke." Panel A opens with a plain-language gloss of the
four assumed terms (AEAD, nonce, nonce-respecting, decryption oracle), and its
state grid animates the real update path `S15 ← A(S0 ⊕ S1) ⊕ A(S13) ⊕ X` on Run
Attack rather than pulsing on a disconnected timer.

## When to Use It

- You need to teach the difference between a security claim and absolute safety.
- You are evaluating an AEAD for a deployment and need to reason about your actual adversary model, not just the scheme's stated security level.
- You want to understand why "no known attack" always has an asterisk.
- You are building systems that expose decryption as a service and need to understand the implications.
- Do NOT treat this as production code or a definitive verdict on HiAE — it is a teaching demo running toy-scale parameters to illustrate a threat-model argument.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-model-breach](https://systemslibrarian.github.io/crypto-lab-model-breach/)**

The demo implements real AESL (one AES round with a zero round key) and a structurally correct toy-scale HiAE, then runs a live attack that actually recovers the key of a toy instance from oracle output — observe the keystream, search the disclosed reduced keyspace for the matching key, and get the decryption oracle to accept a forgery signed with it. The recovered key is verified against the instance. This makes the threat-model point concrete: the forgery step only works because the decryption oracle is exposed, which is outside HiAE's stated model — and the same scheme stays secure under its original nonce-respecting claim.

## What Can Go Wrong

- **The threat model mismatch:** This attack requires both an encryption oracle
  AND a decryption oracle that accepts 2^128 forgery attempts. If your deployment
  cannot expose a decryption oracle to adversaries, you are in the standard model
  and HiAE's 256-bit claim holds.
- **Toy scale vs full scale:** The live recovery brute-forces a *disclosed
  2^16 toy keyspace* against real oracle output — this is what makes an
  end-to-end, honestly-verified key recovery browser-runnable. It is not the
  full algebraic attack: recovering a full random 256-bit key is 2^130 data /
  2^209 time (ePrint 2025/1203) and is annotated, never executed. The paper's
  AESL differential machinery (Theorem 1 enumeration, the MITM key equation)
  is implemented and unit-tested, but the reduced keyspace — not that machinery
  — is what the in-browser recovery drives.
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
No external crypto libraries — the AES round function (AESL) and the toy HiAE
are hand-implemented in `src/` and unit-tested with `vitest` (FIPS-197 round
vector, AEAD round-trip, forgery rejection, and a black-box end-to-end recovery
that would fail if the key were ever read from oracle metadata). WebCrypto
supplies randomness only (the secret toy seed and forgery-probe tags).

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
