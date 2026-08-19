import './style.css';
import { runModelBreachAttack, type AttackProgress } from './attack';
import { toHex } from './bytes';
import { decryptOracle, encryptToyHiAE } from './hiae';
import {
  deriveToyKey,
  SEARCH_WIDTHS,
  seedSpaceFor,
  TOY_AD,
  TOY_NONCE,
  TOY_SEED_BITS,
  TOY_SEED_SPACE,
} from './toykey';
import { ddtCensus, runDifferentialStep, type DifferentialStepResult } from './differential';
import { SBOX } from './aesl';

/** First keystream block a key would produce = ct of a zero block (ct ⊕ 0).
 *  This is exactly A(S0 ⊕ S2) after AD absorption — the block the attack observes
 *  and the equation each candidate key must satisfy. Computed live, not faked. */
function keystreamBlockOf(key: Uint8Array): Uint8Array {
  const zero = new Uint8Array(16);
  return encryptToyHiAE(key, new Uint8Array(TOY_NONCE), zero, new Uint8Array(TOY_AD))
    .ciphertext.subarray(0, 16);
}

type ScenarioId = 'a' | 'b' | 'c';

interface DemoInstance {
  seed: number;
  key: Uint8Array;
  /** The keyspace the learner disclosed when this instance was generated. */
  seedSpace: number;
  nonce: Uint8Array;
  ad: Uint8Array;
}

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) throw new Error('App root not found');

/* ------------------------------------------------------------------ */
/* HTML shell                                                          */
/* ------------------------------------------------------------------ */
app.innerHTML = `
  <a href="#main-content" class="skip-link">Skip to main content</a>
  <div class="page-bg" aria-hidden="true"></div>

  <!-- Fleet hero standard. The shared site header owns role="banner"; the JS in
       index.html demotes any implicit banner, so this <header> gets role="group".
       Dark is the only theme and it is pinned in index.html before first paint,
       so the hero carries no theme control. -->
  <header class="cl-hero">
    <div class="cl-hero-main">
      <h1 class="cl-hero-title">Model Breach</h1>
      <p class="cl-hero-sub">Threat models as contracts · HiAE case study</p>
      <p class="cl-hero-desc">Walk a live case study where HiAE's 256-bit claim holds under its stated model, then watch it fall to 2<sup>209</sup> the moment an unlimited decryption oracle is added to the adversary.</p>
    </div>
    <aside class="cl-hero-why" aria-label="Why it matters">
      <span class="cl-hero-why-label">WHY IT MATTERS</span>
      <p class="cl-hero-why-text">A security proof is a contract with fine print: "secure" only means secure against the stated adversary. Miss the model boundary and you can deploy a provably-broken scheme while believing the headline bit-count.</p>
    </aside>
  </header>

  <main class="panel-grid" id="main-content">

    <!-- ============ PANEL A ============ -->
    <section class="panel" id="panel-a">
      <h2 class="panel-title">THE SECURITY CONTRACT</h2>

      <details class="glossary">
        <summary>New here? Four terms this contract assumes <span class="gloss-hint">(expand)</span></summary>
        <dl class="gloss-list">
          <dt>AEAD</dt>
          <dd>Authenticated Encryption with Associated Data. One primitive that both
            <em>hides</em> a message (encryption) and <em>proves it was not tampered with</em>
            (a short authentication <em>tag</em>). HiAE is an AEAD.</dd>
          <dt>Nonce</dt>
          <dd>A "number used once" fed in alongside the key. It makes each encryption of the
            same message look different. Security depends on never repeating one under the same key.</dd>
          <dt>Nonce-respecting</dt>
          <dd>The adversary model where the attacker never sees two encryptions under the same nonce.
            HiAE's 256-bit claim is made <em>only</em> in this setting.</dd>
          <dt>Decryption oracle</dt>
          <dd>A service the attacker can hand a ciphertext + tag to, that answers
            <em>valid</em> or <em>invalid</em>. Standard AEAD proofs assume the attacker
            cannot lean on this to test unlimited forgeries — the extended model lets them.</dd>
        </dl>
      </details>

      <pre class="contract-block">SCHEME:   HiAE (ePrint 2025/377)
VERSION:  Cross-platform AEAD for 6G networks
CLAIMED:  256-bit security against key-recovery attacks

CONDITIONS:
  \u2713 Nonce-respecting encryption queries
  \u2713 Standard AEAD adversary model
  \u2717 Adversary may NOT submit unlimited forgery attempts
     to the decryption oracle

PERFORMANCE: 340 Gbps (x86) \u00b7 180 Gbps (ARM)
STATUS:  Secure under these conditions \u2713</pre>

      <h3>Full HiAE state (2048-bit)</h3>
      <div id="full-state" class="state-grid"
           aria-label="Full HiAE 16-block state diagram"></div>
      <p class="state-note" id="state-note">Each cell is one 128-bit <strong>state block</strong> \u2014 internal secret memory,
        not the message. Update path: S<sub>15</sub> \u2190 A(S<sub>0</sub> \u2295 S<sub>1</sub>) \u2295 A(S<sub>13</sub>) \u2295 X.
        <span class="state-note-live">On <strong>Run Attack</strong>, the cells feeding S<sub>15</sub>
        (S<sub>0</sub>, S<sub>1</sub>, S<sub>13</sub>) light up in sequence so you can watch the state actually mutate.</span></p>
      <p class="state-caption" id="state-caption" role="status" aria-live="polite">Idle \u2014 the cells narrate themselves once the attack runs.</p>

      <h3>Toy HiAE (4-block reduced)</h3>
      <div class="toy-grid"
           aria-label="Toy HiAE (4-block reduced) state diagram">
        <span class="key-carry">S0</span>
        <span>S1</span>
        <span class="key-carry">S2</span>
        <span>S3</span>
      </div>
      <p class="tiny">Toy HiAE (4-block reduced) \u2014 the live simulation runs on this. The keystream
        the attack captures is <strong>A(S0 \u2295 S2)</strong>, so the red S0/S2 cells are exactly the
        state words the observed leak constrains \u2014 that is what makes recovery possible.</p>
    </section>

    <!-- ============ PANEL B ============ -->
    <section class="panel" id="panel-b">
      <h2 class="panel-title">THE THREAT MODEL MAP</h2>

      <table class="model-table"
             aria-label="Standard vs extended threat model comparison">
        <thead>
          <tr>
            <th scope="col">STANDARD MODEL</th>
            <th scope="col">EXTENDED MODEL (this attack)</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Encrypt with fresh nonces</td>
            <td>Encrypt with fresh nonces \u2713</td>
          </tr>
          <tr>
            <td>Observe ciphertexts</td>
            <td>Observe ciphertexts \u2713</td>
          </tr>
          <tr>
            <td>Try to forge (limited)</td>
            <td>Submit <strong>UNLIMITED</strong> forgeries to decryption oracle until one tag validates \u2717</td>
          </tr>
          <tr>
            <td class="ok-text">HiAE security: 2<sup>256</sup> \u2713</td>
            <td class="danger-text">HiAE security: 2<sup>209</sup> \u2717</td>
          </tr>
        </tbody>
      </table>

      <div class="gap-wrap">
        <p class="gap-title">How big is the breach? (bars are log-scale: length \u221d the exponent)</p>
        <div class="magbars">
          <div class="magbar-row">
            <span class="magbar-name">HiAE claim</span>
            <div class="magbar-track">
              <div class="magbar-fill magbar-claim" style="width:100%">
                <span class="magbar-val">2<sup>256</sup></span>
              </div>
            </div>
          </div>
          <div class="magbar-row">
            <span class="magbar-name">Attack cost</span>
            <div class="magbar-track">
              <div class="magbar-fill magbar-attack" style="width:81.64%">
                <span class="magbar-val">2<sup>209</sup></span>
              </div>
            </div>
          </div>
        </div>
        <p class="tiny gap-quant">The attack does not shave a little off \u2014 it drops the work by
          <strong>2<sup>47</sup></strong>, roughly <strong>140 trillion\u00d7</strong> easier than the headline
          claim. On a log scale that is the whole amber shortfall between the two bars above.</p>
      </div>

      <div class="scenario-tabs" role="tablist"
           aria-label="Real-world deployment scenarios">
        <button role="tab" id="tab-a" aria-selected="true"
                aria-controls="scenario-panel" data-scenario="a">Scenario A</button>
        <button role="tab" id="tab-b" aria-selected="false"
                aria-controls="scenario-panel" data-scenario="b">Scenario B</button>
        <button role="tab" id="tab-c" aria-selected="false"
                aria-controls="scenario-panel" data-scenario="c">Scenario C</button>
      </div>
      <article id="scenario-panel" class="scenario-card" role="tabpanel"></article>
    </section>

    <!-- ============ BRIDGE: WHY THE ORACLE HELPS ============ -->
    <section class="panel" id="panel-oracle">
      <h2 class="panel-title">WHY THE ORACLE CHANGES EVERYTHING</h2>
      <p class="bridge-lede">A candidate key is only useful if you can <em>test</em> it. The one capability the
        extended model adds \u2014 a decryption oracle that answers <strong>valid / invalid</strong> \u2014 is precisely
        what turns "I have a guess" into "I can check my guess." That is the whole reason the number in the table
        moves from 2<sup>256</sup> to 2<sup>209</sup>.</p>

      <div class="oracle-compare">
        <div class="oc-side oc-standard">
          <h3 class="oc-h">Standard model \u2014 ciphertext only</h3>
          <p class="tiny">The attacker sees ciphertext but has no way to ask "is this key right?"
            Each guess is a shot in the dark that can never be confirmed.</p>
          <div class="oc-demo">
            <div class="oc-guess" id="oc-std-guess">candidate keys: none drawn yet</div>
            <div class="oc-verdict oc-unknown" id="oc-std-verdict" role="status" aria-live="polite">— idle</div>
          </div>
          <ul class="oc-list" id="oc-std-list"></ul>
          <button id="oc-std-run" type="button" class="oc-btn">Try to eliminate the candidates</button>
        </div>
        <div class="oc-side oc-extended">
          <h3 class="oc-h">Extended model \u2014 decryption oracle</h3>
          <p class="tiny">The attacker submits a forgery built from each guess. A <strong>reject</strong> throws
            the candidate out; an <strong>accept</strong> confirms it. Guessing becomes searching.</p>
          <div class="oc-demo">
            <div class="oc-guess" id="oc-ext-guess">candidate keys: none drawn yet</div>
            <div class="oc-verdict oc-pending" id="oc-ext-verdict" role="status" aria-live="polite">\u2014 idle</div>
          </div>
          <ul class="oc-list" id="oc-ext-list"></ul>
          <button id="oc-run" type="button" class="oc-btn">Ask the oracle</button>
        </div>
      </div>
      <p class="tiny oc-caption">The <em>same</em> candidate list, two worlds. <strong>Press both buttons.</strong>
        The left side runs the only test a ciphertext-only attacker has \u2014 for each candidate key it computes the
        plaintext that key implies for the intercepted ciphertext \u2014 and finds that every candidate implies
        <em>some</em> plaintext, so not one of them can be ruled out. That is not a spinner giving up; it is the
        predicate being vacuous, counted. The right side submits the same candidates as real forgeries and the oracle
        answers, so all but one are eliminated. The counts under each button come from that run.</p>
    </section>

    <!-- ============ PANEL C ============ -->
    <section class="panel" id="panel-c">
      <h2 class="panel-title">LIVE SIMULATION \u2014 TOY HIAE (4-BLOCK REDUCED)</h2>

      <!-- Always-visible micro-explainer: makes the single-query leak concrete
           BEFORE the jargon lede. Encrypt a zero block -> ct = pt XOR keystream,
           so with pt = 0 the ciphertext IS the keystream block A(S0 XOR S2).
           All three rows are computed live from the toy scheme, not faked. -->
      <div class="leak-explainer">
        <h3 class="leak-h">First, what is a "keystream leak"?</h3>
        <p class="tiny leak-source" id="leak-source"></p>
        <p class="leak-lede">A stream cipher hides a message by XOR-ing it with a secret
          <strong>keystream</strong>: <span class="mono">ciphertext = plaintext \u2295 keystream</span>.
          Watch what happens if the attacker asks the encryption oracle to encrypt a block of
          <strong>all zeros</strong>. Because <span class="mono">0 \u2295 keystream = keystream</span>,
          the ciphertext that comes back <em>is</em> the keystream block itself \u2014 which for this 4-block toy HiAE is exactly
          <span class="mono">A(S0 \u2295 S2)</span>. One query, and a piece of the secret state leaks out in the clear.</p>
        <div class="leak-rows">
          <div class="leak-row">
            <span class="leak-label">Plaintext (all zeros)</span>
            <div class="leak-bytes" id="leak-pt"></div>
          </div>
          <div class="leak-row">
            <span class="leak-label">Ciphertext back from oracle</span>
            <div class="leak-bytes" id="leak-ct"></div>
          </div>
          <div class="leak-row">
            <span class="leak-label">\u2234 Derived keystream <span class="mono">A(S0\u2295S2)</span> = ct \u2295 0</span>
            <div class="leak-bytes" id="leak-ks"></div>
          </div>
        </div>
        <p class="tiny leak-foot">The bottom two rows are identical byte-for-byte \u2014 that is the whole point:
          encrypting zeros hands the attacker the keystream directly. The attack below turns this one leaked
          block into an <em>equation</em> every candidate key must satisfy.</p>
      </div>

      <p class="mech-lede">The break is <strong>not</strong> "try every number." It is: the observed keystream
        <span class="mono">A(S0 \u2295 S2)</span> is an <em>equation</em>, and a candidate key is kept only if it
        <em>satisfies</em> that equation \u2014 reproduces the observed block byte-for-byte. Below, watch candidates get
        <strong>checked</strong> against the leak, not merely counted.</p>

      <div class="keystream-viz" id="keystream-viz" aria-hidden="true">
        <div class="kv-row">
          <span class="kv-label">Observed leak <span class="mono">A(S0\u2295S2)</span></span>
          <div class="kv-bytes" id="kv-observed"></div>
        </div>
        <div class="kv-row">
          <span class="kv-label" id="kv-cand-label">Candidate re-derives</span>
          <div class="kv-bytes" id="kv-candidate"></div>
        </div>
        <p class="kv-status" id="kv-status">Generate an instance and run the attack to see the equation check.</p>
      </div>

      <!-- Method-honesty callout: the browser's toy seed search and the paper's
           2^209 differential attack are DIFFERENT techniques, not the same method
           at two sizes. Prevents the false "the paper just brute-forces bigger". -->
      <div class="method-contrast">
        <h3 class="mc-h">Two different methods — not one method at two sizes</h3>
        <div class="mc-cols">
          <div class="mc-col mc-browser">
            <span class="mc-tag">WHAT THIS BROWSER DOES</span>
            <ul>
              <li><strong>Exhaustive seed search.</strong> It walks all 2<sup>16</sup> keys in the disclosed toy keyspace.</li>
              <li>For each one it re-derives <span class="mono">A(S0⊕S2)</span> and keeps the key whose block matches the leak.</li>
              <li>Feasible in a browser <em>only</em> because the keyspace was deliberately shrunk to 2<sup>16</sup>.</li>
            </ul>
          </div>
          <div class="mc-col mc-paper">
            <span class="mc-tag">WHAT THE PAPER DOES</span>
            <ul>
              <li><strong>Meet-in-the-middle differential algebra.</strong> It never enumerates 2<sup>209</sup> keys.</li>
              <li>It solves the AESL structure with a guess-and-determine + differential technique to <em>cut</em> the work to 2<sup>209</sup>.</li>
              <li>You can run that differential step yourself, on real AESL output, in the panel directly below.
                What stays annotated is <em>chaining</em> it across the full 2048-bit state.</li>
            </ul>
          </div>
        </div>
        <p class="tiny mc-foot"><strong>These are not the same algorithm.</strong> The toy is a faithful
          end-to-end <em>stand-in</em> that shows the leak → recover → forge story truthfully; it is not a
          scaled-down copy of ePrint 2025/1203. Believing the real attack is "just this search, bigger" is the
          one wrong lesson to take from this page.</p>
      </div>

      <!-- ============ THE PAPER'S TECHNIQUE, EXECUTED ============ -->
      <div class="diffstep" id="diffstep">
        <h3 class="ds-h">Run the paper's technique — the differential step, measured</h3>
        <p class="ds-lede">The seed search above is the stand-in. <em>This</em> is the paper's actual move, running
          on real AESL output. Plant a state pair differing by <span class="mono">α</span>, read the output difference
          <span class="mono">β = AESL(x) ⊕ AESL(x ⊕ α)</span>, and watch what knowing β does to the search space:
          each active S-box stops accepting all 256 inputs and accepts only those satisfying
          <span class="mono">S(x) ⊕ S(x ⊕ δ<sub>in</sub>) = δ<sub>out</sub></span>. Every number below is measured from
          the run, including the enumeration's own candidate count.</p>

        <div class="ds-ddt" id="ds-ddt">
          <h4 class="ds-sub">Why it pays — the AES S-box difference table, counted here on load</h4>
          <div class="ds-stats" id="ds-ddt-stats"></div>
          <p class="tiny" id="ds-ddt-note"></p>
        </div>

        <div class="actions">
          <button id="run-diffstep" type="button">Run the differential step</button>
        </div>
        <p id="ds-meta" class="tiny" role="status" aria-live="polite">Not run yet.</p>
        <div id="diffstep-out" class="ds-out" hidden></div>

        <p class="tiny ds-scale"><strong>Scale, plainly:</strong> this runs the differential step on
          <em>one</em> AESL call with four active S-boxes — the size a browser can afford. The paper chains the same
          step across HiAE's 2048-bit state, and that chaining is where 2<sup>209</sup> comes from. The chaining is
          not executed here and this panel does not claim it: what it claims, and measures, is the per-step collapse.</p>
      </div>

      <div class="attack-controls">
        <div class="ac-field">
          <label for="seed-width">Disclosed keyspace</label>
          <select id="seed-width">
            ${SEARCH_WIDTHS.map((b) => `<option value="${b}"${b === 16 ? ' selected' : ''}>2^${b} keys</option>`).join('')}
          </select>
        </div>
        <div class="ac-field">
          <label for="seed-choice">Secret seed</label>
          <input id="seed-choice" type="text" inputmode="numeric" placeholder="random" size="10" />
        </div>
        <p class="tiny ac-hint" id="seed-hint">Leave the seed blank to draw one at random, or type a decimal or
          0x-prefixed value to place it yourself. A seed near the start of the space is found after a handful of
          candidates and one near the end after nearly all of them; the run table below records what each run cost.</p>
      </div>

      <div class="actions">
        <button id="generate-instance" type="button">Generate Instance</button>
        <button id="run-attack" type="button" disabled>Run Attack</button>
      </div>
      <p id="instance-meta" class="tiny" role="status" aria-live="polite">Oracles not initialized yet.</p>
      <p id="oracle-state" class="tiny oracle-state" role="status" aria-live="polite"></p>
      <table class="run-table" id="run-table" hidden>
        <caption>Every completed run, as measured</caption>
        <thead>
          <tr><th scope="col">Keyspace</th><th scope="col">Seed</th><th scope="col">Candidates tested</th><th scope="col">Search time</th><th scope="col">Forgery confirmed</th></tr>
        </thead>
        <tbody id="run-table-body"></tbody>
      </table>

      <div id="attack-log" class="attack-log" role="log"
           tabindex="0" aria-live="polite"
           aria-label="Attack simulation log — scrollable"></div>

      <div id="forge-result" class="forge-result hidden" aria-label="Forgery verification result">
        <h3 class="fr-h">What "the contract broke" actually means</h3>
        <div class="fr-cards">
          <div class="fr-card fr-accept" id="fr-accept">
            <span class="fr-badge">✓ ACCEPTED</span>
            <p>Forgery signed with the <strong>recovered</strong> key.
              The decryption oracle validated it — a message the attacker forged is treated as authentic.</p>
          </div>
          <div class="fr-card fr-reject" id="fr-reject">
            <span class="fr-badge">✗ REJECTED</span>
            <p>Same ciphertext, but a <strong>random</strong> tag.
              The oracle rejected it — proof the accept above is meaningful, not an oracle that says yes to everything.</p>
          </div>
        </div>
        <p class="tiny fr-note">The accept is the felt version of "2<sup>209</sup>": inside the extended model, the
          attacker's forgery goes through. Under HiAE's stated nonce-respecting model, no such oracle exists — and the
          claim holds.</p>
      </div>

      <aside id="disclaimer" class="disclaimer hidden"
             aria-label="Threat model reminder">
        <strong>\u26A0 WHAT JUST RAN \u2014 AND WHAT DID NOT</strong>
        <p>The recovered key above is <strong>genuinely computed</strong>: the
           attack observed the encryption oracle\u2019s keystream, then searched the
           <em>disclosed reduced toy keyspace</em> (2<sup>${TOY_SEED_BITS}</sup>
           seeds) for the one key that reproduces it, and confirmed it by getting
           the <strong>decryption oracle to accept a forgery</strong> signed with
           that key. No ground-truth key was read.</p>
        <p>The reduced keyspace is the toy. Recovering a full random 256-bit HiAE
           key is the 2<sup>209</sup>-time / 2<sup>130</sup>-data result of ePrint
           2025/1203 \u2014 that is annotated, never executed in-browser.</p>
        <p>The forgery step needs a decryption oracle that accepts adversarial
           ciphertexts \u2014 outside HiAE\u2019s stated model.
           Whether that matters depends on your deployment \u2014 see Panel B.</p>
        <p>Full paper:
          <a href="https://eprint.iacr.org/2025/1203.pdf"
             target="_blank" rel="noreferrer">ePrint 2025/1203<span class="sr-only"> (opens in new tab)</span></a></p>
      </aside>
    </section>

    <!-- ============ PANEL D ============ -->
    <section class="panel" id="panel-d">
      <h2 class="panel-title">THE ACADEMIC RECORD</h2>

      <div class="timeline">
        <div class="tl-entry">
          <b>Jun 2025</b>
          <span>ePrint 2025/1203 \u2014 Hu et al.<br>
          \u201CBreaking The Authenticated Encryption Scheme HiAE\u201D<br>
          Attack: 2<sup>209</sup> time, 2<sup>130</sup> data.
          Extended decryption oracle model.</span>
          <a href="https://eprint.iacr.org/2025/1203.pdf"
             target="_blank" rel="noreferrer">View Paper \u2197<span class="sr-only"> (opens in new tab)</span></a>
        </div>
        <div class="tl-entry">
          <b>Jun 2025</b>
          <span>ePrint 2025/1180 \u2014 Bille &amp; Tischhauser (concurrent, independent)<br>
          \u201CCryptanalysis of HiAE\u201D \u2014 independent confirmation of the
          extended-model vulnerability. Two papers, same result, same week.</span>
        </div>
        <div class="tl-entry">
          <b>Jul 2025</b>
          <span>ePrint 2025/1235 \u2014 HiAE Designers\u2019 Response<br>
          \u201CHiAE remains secure in its intended model.\u201D<br>
          \u201CThe attack operates outside Section 4.5 of our paper.\u201D<br>
          HiAE security claims: intact under standard model.</span>
          <a href="https://eprint.iacr.org/2025/1235.pdf"
             target="_blank" rel="noreferrer">View Response \u2197<span class="sr-only"> (opens in new tab)</span></a>
        </div>
      </div>

      <div class="verdict-grid">
        <div>
          <h3 class="verdict-h">WHAT THE PAPER SHOWS</h3>
          <p>HiAE security falls to 2<sup>209</sup> in the extended oracle model.</p>
          <p>The byte-decomposition technique is novel and generalizes to other AEADs.</p>
          <p>The IETF draft should discuss extended adversary models explicitly.</p>
        </div>
        <div>
          <h3 class="verdict-h">WHAT IT DOES NOT SHOW</h3>
          <p>HiAE is not invalidated for standard-model deployments.</p>
          <p>HiAE\u2019s performance or design is flawed \u2014 it is genuinely excellent engineering.</p>
          <p>The IETF draft should be withdrawn.</p>
        </div>
      </div>

      <blockquote class="lesson">
        <p>\u201CSecure\u201D always means \u201Csecure against <em>these</em> adversaries
        under <em>these</em> assumptions.\u201D</p>
        <p>The assumptions are the contract.<br>
        The threat model is the fine print.</p>
        <p><strong>Read both before deploying anything.</strong></p>
      </blockquote>
    </section>

  </main>

  <footer>
    <p class="related-demos">Related demos:
      <a href="https://systemslibrarian.github.io/crypto-lab-nonce-guard/" target="_blank" rel="noreferrer">crypto-lab-nonce-guard</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-aes-modes/" target="_blank" rel="noreferrer">crypto-lab-aes-modes</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-ascon/" target="_blank" rel="noreferrer">crypto-lab-ascon</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-aegis-gate/" target="_blank" rel="noreferrer">crypto-lab-aegis-gate</a>
      <a href="https://systemslibrarian.github.io/crypto-lab-protocol-compose/" target="_blank" rel="noreferrer">crypto-lab-protocol-compose</a>
    </p>
    <p>\u201CWhether therefore ye eat, or drink, or whatsoever ye do,
    do all to the glory of God.\u201D \u2014 1 Corinthians 10:31</p>
  </footer>
`;

/* ------------------------------------------------------------------ */
/* Cached DOM references                                               */
/* ------------------------------------------------------------------ */
function $(id: string): HTMLElement {
  const el = document.getElementById(id);
  if (!el) throw new Error('Missing #' + id);
  return el;
}

const scenarioPanelEl = $('scenario-panel');
const generateBtnEl   = $('generate-instance') as HTMLButtonElement;
const runBtnEl        = $('run-attack') as HTMLButtonElement;
const instanceMetaEl  = $('instance-meta');
const attackLogEl     = $('attack-log');
const disclaimerEl    = $('disclaimer');
const forgeResultEl   = $('forge-result');
const kvObservedEl    = $('kv-observed');
const kvCandidateEl   = $('kv-candidate');
const kvStatusEl      = $('kv-status');
const kvCandLabelEl   = $('kv-cand-label');
const kvVizEl         = $('keystream-viz');
const leakSourceEl    = $('leak-source');
const oracleStateEl   = $('oracle-state');
const seedWidthEl     = $('seed-width') as HTMLSelectElement;
const seedChoiceEl    = $('seed-choice') as HTMLInputElement;
const runTableEl      = $('run-table') as HTMLTableElement;
const runTableBodyEl  = $('run-table-body');

/* ------------------------------------------------------------------ */
/* Leak micro-explainer (Panel C) — render the three concrete rows      */
/* (zero plaintext, ciphertext, derived keystream) live so the learner  */
/* SEES that ct-of-zeros IS the keystream block A(S0 ⊕ S2).             */
/* ------------------------------------------------------------------ */
function renderLeakBytes(container: HTMLElement, bytes: Uint8Array, cls = ''): void {
  container.textContent = '';
  for (let i = 0; i < bytes.length; i++) {
    const cell = document.createElement('span');
    cell.className = 'leak-byte' + (cls ? ' ' + cls : '');
    cell.textContent = bytes[i].toString(16).padStart(2, '0');
    container.appendChild(cell);
  }
}

/**
 * Render the three leak rows for a specific key.
 *
 * These rows used to be computed from `deriveToyKey(0x1a2b)` — a fixed key with
 * no relationship to the instance being attacked below. The bytes were real,
 * but they were the wrong bytes: the learner was shown "the keystream the
 * attacker observes" for a key the attacker never touches, and could compare
 * them against the attack's own observed leak and find no correspondence at
 * all. Once an instance exists these rows show *its* leak, which is exactly the
 * block phase 1 captures. The seed stays secret; the keystream does not, which
 * is the whole point of the panel.
 */
function renderLeakExplainer(key: Uint8Array, source: string): void {
  const zero = new Uint8Array(16);
  const out = encryptToyHiAE(key, new Uint8Array(TOY_NONCE), zero, new Uint8Array(TOY_AD));
  const ct = out.ciphertext.subarray(0, 16);
  const ks = keystreamBlockOf(key); // == ct, since pt is all zeros
  renderLeakBytes($('leak-pt'), zero, 'leak-zero');
  renderLeakBytes($('leak-ct'), ct);
  renderLeakBytes($('leak-ks'), ks, 'leak-derived');
  leakSourceEl.textContent = source;
}

renderLeakExplainer(
  deriveToyKey(0x1a2b),
  'Showing an illustrative key, because no instance has been generated yet. ' +
    'Generate one below and these rows become that instance\u2019s own leak \u2014 the exact block the attack captures.',
);

/* ------------------------------------------------------------------ */
/* The paper's technique, executed (Panel C)                           */
/* The differential step from ePrint 2025/1203 run on real AESL output, */
/* with the search-space collapse it produces measured on each run      */
/* rather than described. The DDT census below is counted on load.      */
/* ------------------------------------------------------------------ */
function fmtCount(n: number): string {
  return n.toLocaleString('en-US');
}

function statBlock(label: string, value: string, cls = ''): string {
  return `<div class="ds-stat${cls ? ' ' + cls : ''}"><span class="ds-stat-val">${value}</span><span class="ds-stat-lbl">${label}</span></div>`;
}

(function renderDdtCensus() {
  const census = ddtCensus(SBOX);
  $('ds-ddt-stats').innerHTML =
    statBlock('(δin, δout) pairs counted', fmtCount(census.pairs)) +
    statBlock('pairs with NO solution', fmtCount(census.withZero)) +
    statBlock('pairs with 2 solutions', fmtCount(census.withTwo)) +
    statBlock('pairs with 4 solutions', fmtCount(census.withFour)) +
    statBlock('mean solutions per pair', census.meanSolutionsPerPair.toFixed(2), 'ds-stat-key');
  $('ds-ddt-note').textContent =
    'Counted by building the table: ' + fmtCount(census.totalSolutions) + ' solutions spread over ' +
    fmtCount(census.pairs) + ' difference pairs, so an active S-box whose output difference is known keeps ' +
    census.meanSolutionsPerPair.toFixed(2) + ' input on average instead of 256. ' +
    'Slightly over half the pairs are impossible outright, which is why a wrong differential dies immediately.';
})();

function renderDifferentialRun(r: DifferentialStepResult): string {
  const hexOf = (b: Uint8Array) => Array.from(b).map(v => v.toString(16).padStart(2, '0')).join('');
  const rows = r.constraints
    .map(
      c => `<tr>
        <td>byte ${c.index}</td>
        <td class="mono">0x${c.deltaIn.toString(16).padStart(2, '0')}</td>
        <td class="mono">0x${c.deltaOut.toString(16).padStart(2, '0')}</td>
        <td class="mono">${c.candidates.length}</td>
        <td class="mono">${c.candidates.map(v => '0x' + v.toString(16).padStart(2, '0')).join(' ') || '—'}</td>
      </tr>`,
    )
    .join('');

  const allOk = r.solved && r.betaReproduced && r.matchesPlanted;
  const check = (ok: boolean, text: string) =>
    `<p class="ds-check ${ok ? 'ok-text' : 'danger-text'}"><span aria-hidden="true">${ok ? '✓' : '✗'}</span> ${text}</p>`;

  return `
    <div class="ds-diff">
      <p class="ds-row"><span class="ds-row-lbl">α (input difference)</span><span class="mono ds-row-val" id="ds-alpha">${hexOf(r.alpha)}</span></p>
      <p class="ds-row"><span class="ds-row-lbl">β = AESL(x) ⊕ AESL(x ⊕ α)</span><span class="mono ds-row-val" id="ds-beta">${hexOf(r.beta)}</span></p>
    </div>
    <table class="ds-table" aria-label="Active S-box differential constraints for this run">
      <thead><tr><th scope="col">Active S-box</th><th scope="col">δ<sub>in</sub></th><th scope="col">δ<sub>out</sub></th><th scope="col">solutions</th><th scope="col">which inputs</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <div class="ds-stats">
      ${statBlock('active S-boxes', String(r.activeSboxes))}
      ${statBlock('space knowing α only', '2^' + r.naiveBits.toFixed(0))}
      ${statBlock('space knowing α and β', '2^' + r.survivingBits.toFixed(0), 'ds-stat-key')}
      ${statBlock('measured reduction', '2^' + r.reductionBits.toFixed(0), 'ds-stat-key')}
      ${statBlock('candidate pairs enumerated', fmtCount(r.candidatesEnumerated))}
      ${statBlock('enumeration time', r.elapsedMs.toFixed(1) + ' ms')}
    </div>
    <div class="ds-checks" id="ds-checks">
      ${check(r.solved, 'The Theorem 1 enumeration returned a single surviving state.')}
      ${check(r.betaReproduced, 'That state re-derives the observed β under real AESL — the differential is satisfied, not assumed.')}
      ${check(r.matchesPlanted, 'It equals the state that was planted, which the enumeration was never told.')}
    </div>
    <p class="ds-verdict ${allOk ? 'ok-text' : 'danger-text'}" id="ds-verdict">${
      allOk
        ? 'Knowing β collapsed ' + fmtCount(r.naiveSpace) + ' possibilities to ' + fmtCount(r.survivingSpace) +
          ' — a measured 2^' + r.reductionBits.toFixed(0) + ' cut, from one differential, on one AESL call.'
        : 'This differential did not pin down a unique state. Run it again — that outcome is reported, not hidden.'
    }</p>`;
}

const dsOutEl = $('diffstep-out');
const dsMetaEl = $('ds-meta');
const dsRunBtnEl = $('run-diffstep') as HTMLButtonElement;

dsRunBtnEl.addEventListener('click', () => {
  dsRunBtnEl.disabled = true;
  try {
    const result = runDifferentialStep();
    dsOutEl.innerHTML = renderDifferentialRun(result);
    dsOutEl.hidden = false;
    dsMetaEl.textContent =
      'Ran on a fresh random pair: ' + result.activeSboxes + ' active S-boxes, ' +
      fmtCount(result.candidatesEnumerated) + ' candidate pairs enumerated in ' +
      result.elapsedMs.toFixed(1) + ' ms. Press again for a different differential.';
  } finally {
    dsRunBtnEl.disabled = false;
  }
});

/* ------------------------------------------------------------------ */
/* Scenario tabs                                                       */
/* ------------------------------------------------------------------ */
const scenarios: Record<ScenarioId, { text: string; cls: string; decryptionOracle: boolean }> = {
  a: {
    text: 'Scenario A: 6G base station \u2014 Attacker can observe traffic but cannot submit forgeries to the decryption pipeline. Standard model applies. HiAE is safe. \u2713',
    cls: 'ok',
    decryptionOracle: false,
  },
  b: {
    text: 'Scenario B: Shared API endpoint \u2014 Decryption is exposed as a service. Attacker can submit forged ciphertexts. Extended model applies. HiAE security falls to 2^209. \u26A0',
    cls: 'warn',
    decryptionOracle: true,
  },
  c: {
    text: 'Scenario C: GPU interconnect \u2014 Point-to-point hardware link. No decryption oracle exposure. Standard model applies. HiAE is safe. \u2713',
    cls: 'ok',
    decryptionOracle: false,
  },
};

/**
 * The selected scenario is now a contract the simulation below obeys, not a
 * caption beside it. Under A and C the attack is handed no decryption oracle at
 * all, so its forge phase has nothing to submit to and the run ends with an
 * unconfirmed candidate. Previously all three tabs ran the identical attack to
 * the identical "forgery ACCEPTED", which quietly contradicted the two tabs
 * that said no such pipeline is exposed.
 */
let activeScenario: ScenarioId = 'a';

function oracleExposed(): boolean {
  return scenarios[activeScenario].decryptionOracle;
}

function setScenario(id: ScenarioId): void {
  const changed = id !== activeScenario;
  activeScenario = id;
  document.querySelectorAll<HTMLButtonElement>('[role="tab"]').forEach(tab => {
    const active = tab.dataset.scenario === id;
    tab.setAttribute('aria-selected', String(active));
    tab.classList.toggle('active', active);
    tab.setAttribute('tabindex', active ? '0' : '-1');
  });
  scenarioPanelEl.textContent = scenarios[id].text;
  scenarioPanelEl.className = 'scenario-card ' + scenarios[id].cls;
  scenarioPanelEl.setAttribute('aria-labelledby', 'tab-' + id);
  paintOracleState();
  // A finished run describes the deployment it ran against. Switching
  // deployments retires it rather than leaving a "forgery ACCEPTED" log under a
  // tab that says no forgeries can be submitted.
  if (changed) retireAttackRun();
}

// Scenario A is the default view, and now also the default *contract*: no
// decryption oracle until the learner selects the deployment that has one.
setScenario('a');

document.querySelectorAll<HTMLButtonElement>('[role="tab"]').forEach(tab => {
  tab.addEventListener('click', () => {
    setScenario(tab.dataset.scenario as ScenarioId);
  });
  tab.addEventListener('keydown', (e: KeyboardEvent) => {
    const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
    const idx = tabs.indexOf(tab);
    let next = -1;
    if (e.key === 'ArrowRight') next = (idx + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') next = (idx - 1 + tabs.length) % tabs.length;
    if (next >= 0) {
      e.preventDefault();
      tabs[next].focus();
      tabs[next].click();
    }
  });
});

/* ------------------------------------------------------------------ */
/* Panel A \u2014 state animation                                           */
/* ------------------------------------------------------------------ */
const fullState = $('full-state');
for (let i = 0; i < 16; i++) {
  const cell = document.createElement('div');
  cell.className = 'state-cell';
  // The keystream the attack captures is A(S0 ⊕ S2); mark those as the words the
  // observed leak constrains, matching the toy grid's red cells.
  if (i === 0 || i === 2) cell.classList.add('key-carry');
  cell.textContent = 'S' + i;
  fullState.appendChild(cell);
}

const prefersReducedMotion =
  window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;

// Drive the state grid from the ACTUAL update path S15 ← A(S0 ⊕ S1) ⊕ A(S13) ⊕ X:
// on Run Attack, highlight the source cells (S0, S1, S13) one at a time, then the
// destination S15, so the animation shows the scheme genuinely mutating rather
// than pulsing on a disconnected timer. Reduced-motion users get a single static
// highlight of the same source/destination cells (no timers, no flashing).
const stateCaptionEl = $('state-caption');

// Per-cell gloss tying each highlighted block back to the leak the attack reads,
// so the moving cells carry meaning instead of reading as decoration.
const CELL_CAPTIONS: Record<number, string> = {
  0: 'S0 — one of the two blocks that build the keystream A(S0 ⊕ S2) the attack observes.',
  1: 'S1 — mixes with S0 through the AES round A() to feed the new block.',
  13: 'S13 — the second source run through A() before it lands in S15.',
  15: 'S15 — where the freshly mixed value lands. This is the state actually mutating each step.',
};

function animateUpdatePath(): void {
  const cells = fullState.querySelectorAll<HTMLDivElement>('.state-cell');
  cells.forEach(c => c.classList.remove('pulse', 'update-src', 'update-dst'));
  const src = [0, 1, 13];

  if (prefersReducedMotion) {
    src.forEach(i => cells[i]?.classList.add('update-src'));
    cells[15]?.classList.add('update-dst');
    stateCaptionEl.textContent =
      'S0, S2 feed the keystream A(S0 ⊕ S2) the attack reads; S0/S1/S13 feed the update, and S15 is where the new mixing lands.';
    return;
  }

  let step = 0;
  const total = src.length + 1;
  stateCaptionEl.textContent = 'Watch: the blocks that feed S15 light up one at a time.';
  const timer = window.setInterval(() => {
    if (step < src.length) {
      const i = src[step];
      cells[i]?.classList.add('update-src');
      cells[i]?.classList.add('pulse');
      stateCaptionEl.textContent = CELL_CAPTIONS[i] ?? '';
    } else {
      cells[15]?.classList.add('update-dst');
      cells[15]?.classList.add('pulse');
      stateCaptionEl.textContent = CELL_CAPTIONS[15];
    }
    step++;
    if (step >= total) {
      window.clearInterval(timer);
      window.setTimeout(() => {
        cells.forEach(c => c.classList.remove('pulse', 'update-src', 'update-dst'));
        stateCaptionEl.textContent =
          'S0, S2 feed the keystream you observe; S15 is where the new mixing lands each step.';
      }, 1600);
    }
  }, 550);
}

/* ------------------------------------------------------------------ */
/* Panel C \u2014 Attack helpers                                            */
/* ------------------------------------------------------------------ */
let instance: DemoInstance | null = null;

/**
 * Say, next to the buttons, whether this deployment exposes a decryption
 * oracle — the single fact that decides whether phase 3 can run at all.
 */
function paintOracleState(): void {
  const exposed = oracleExposed();
  oracleStateEl.textContent = exposed
    ? 'Scenario ' + activeScenario.toUpperCase() + ' exposes a decryption oracle, so a recovered key can be ' +
      'confirmed by forging against it. The extended model applies.'
    : 'Scenario ' + activeScenario.toUpperCase() + ' exposes no decryption oracle. The attack below is handed ' +
      'none, so its forge phase will have nothing to submit to and the recovered candidate stays unconfirmed. ' +
      'Switch to Scenario B to give the attacker one.';
  oracleStateEl.className = 'tiny oracle-state ' + (exposed ? 'oracle-open' : 'oracle-shut');
}

/**
 * Drop everything a finished run produced. Called when the deployment or the
 * instance changes underneath it, so no log, forge card or equation grid
 * outlives the conditions it was computed under.
 */
function retireAttackRun(): void {
  attackLogEl.innerHTML = '';
  disclaimerEl.classList.add('hidden');
  forgeResultEl.classList.add('hidden');
  kvVizEl.setAttribute('aria-hidden', 'true');
  kvObservedEl.textContent = '';
  kvCandidateEl.textContent = '';
  kvCandLabelEl.textContent = 'Candidate re-derives';
  kvStatusEl.className = 'kv-status';
}

/** Append one measured row to the run table. Nothing here is a constant. */
function recordRun(row: {
  seedSpace: number;
  seed: number;
  tested: number;
  ms: number;
  confirmed: boolean;
  oracleAvailable: boolean;
}): void {
  const tr = document.createElement('tr');
  const cells = [
    '2^' + Math.log2(row.seedSpace).toFixed(0),
    '0x' + row.seed.toString(16).padStart(4, '0'),
    row.tested.toLocaleString('en-US') + ' of ' + row.seedSpace.toLocaleString('en-US'),
    row.ms + ' ms',
    row.oracleAvailable ? (row.confirmed ? 'yes' : 'no') : 'no oracle to ask',
  ];
  for (const value of cells) {
    const td = document.createElement('td');
    td.textContent = value;
    tr.appendChild(td);
  }
  runTableBodyEl.appendChild(tr);
  runTableEl.hidden = false;
}

/** Read the learner's seed box: blank means draw at random. */
function chooseSeed(seedSpace: number): number {
  const raw = seedChoiceEl.value.trim();
  if (raw !== '') {
    const parsed = /^0[xX][0-9a-fA-F]+$/.test(raw) ? Number.parseInt(raw.slice(2), 16) : Number(raw);
    if (Number.isFinite(parsed) && parsed >= 0) {
      return Math.trunc(parsed) % seedSpace;
    }
  }
  const bytes = new Uint8Array(2);
  crypto.getRandomValues(bytes);
  return ((bytes[0] | (bytes[1] << 8)) >>> 0) % seedSpace;
}

function appendLog(line: string, cssClass = ''): void {
  const p = document.createElement('p');
  p.textContent = line;
  if (cssClass) p.className = cssClass;
  attackLogEl.appendChild(p);
  attackLogEl.scrollTop = attackLogEl.scrollHeight;
}

function appendBadge(line: string, toy: string, full: string): void {
  const p = document.createElement('p');
  const txt = document.createTextNode(line + ' ');
  p.appendChild(txt);
  const badge = document.createElement('span');
  badge.className = 'complexity-badge';
  badge.textContent = '[TOY: ' + toy + '] [FULL: ' + full + ']';
  p.appendChild(badge);
  attackLogEl.appendChild(p);
  attackLogEl.scrollTop = attackLogEl.scrollHeight;
}

/* ------------------------------------------------------------------ */
/* Keystream equation-check visual (Panel C)                           */
/* Shows the recovery as "satisfy the observed equation A(S0 XOR S2)", */
/* not "count seeds". Renders 16 byte cells for the observed leak and  */
/* 16 for the candidate, lighting matches green / mismatches red.      */
/* ------------------------------------------------------------------ */
function renderByteRow(container: HTMLElement, bytes: Uint8Array): HTMLSpanElement[] {
  container.textContent = '';
  const cells: HTMLSpanElement[] = [];
  for (let i = 0; i < bytes.length; i++) {
    const cell = document.createElement('span');
    cell.className = 'kv-byte';
    cell.textContent = bytes[i].toString(16).padStart(2, '0');
    container.appendChild(cell);
    cells.push(cell);
  }
  return cells;
}

/** Paint per-byte match state of a candidate row against the observed leak. */
function markCandidateMatch(cells: HTMLSpanElement[], candidate: Uint8Array, observed: Uint8Array): number {
  let matched = 0;
  for (let i = 0; i < cells.length; i++) {
    const ok = candidate[i] === observed[i];
    cells[i].classList.toggle('kv-match', ok);
    cells[i].classList.toggle('kv-miss', !ok);
    if (ok) matched++;
  }
  return matched;
}

const sleep = (ms: number) => new Promise<void>(r => window.setTimeout(r, ms));

/**
 * Walk the equation check on screen: show the observed leak, then re-derive the
 * keystream for a few WRONG candidate keys (mostly mismatching bytes) before
 * landing on the correct one (all 16 bytes match). Every keystream shown is
 * computed live from deriveToyKey \u2014 nothing is faked; wrong candidates really do
 * fail the equation and the right one really satisfies it.
 */
async function animateEquationCheck(
  observed: Uint8Array,
  correctSeed: number,
  seedSpace: number,
): Promise<void> {
  kvVizEl.setAttribute('aria-hidden', 'false');
  const obsCells = renderByteRow(kvObservedEl, observed);
  obsCells.forEach(c => c.classList.add('kv-observed'));

  const stepMs = prefersReducedMotion ? 0 : 260;

  // A handful of decoy seeds that are NOT the answer, to show the equation
  // rejecting wrong keys byte-by-byte.
  const decoys: number[] = [];
  for (let d = 1; d <= 3; d++) {
    // Decoys must come from the keyspace the attacker was told to search;
    // showing a rejected candidate from outside it would be a candidate the
    // attack never considered.
    const s = (correctSeed + d * 9973) % seedSpace;
    if (s !== correctSeed) decoys.push(s);
  }

  for (const seed of decoys) {
    const cand = keystreamBlockOf(deriveToyKey(seed));
    const cells = renderByteRow(kvCandidateEl, cand);
    kvCandLabelEl.textContent = 'Candidate 0x' + seed.toString(16).padStart(4, '0') + ' re-derives';
    const matched = markCandidateMatch(cells, cand, observed);
    kvStatusEl.textContent =
      'Candidate 0x' + seed.toString(16).padStart(4, '0') + ': ' + matched +
      '/16 bytes satisfy the equation \u2192 rejected. The leak is a constraint, not a counter.';
    kvStatusEl.className = 'kv-status kv-status-miss';
    if (stepMs) await sleep(stepMs * 2);
  }

  // The correct seed: every byte satisfies the equation.
  const correct = keystreamBlockOf(deriveToyKey(correctSeed));
  const cells = renderByteRow(kvCandidateEl, correct);
  kvCandLabelEl.textContent = 'Candidate 0x' + correctSeed.toString(16).padStart(4, '0') + ' re-derives';
  const matched = markCandidateMatch(cells, correct, observed);
  kvStatusEl.textContent =
    '\u2713 Candidate 0x' + correctSeed.toString(16).padStart(4, '0') + ': all ' + matched +
    '/16 bytes satisfy A(S0\u2295S2) \u2014 the equation is solved, so this key is the recovered key. Not brute luck: a constraint met.';
  kvStatusEl.className = 'kv-status kv-status-match';
  if (stepMs) await sleep(stepMs * 2);
}

function renderProgress(prog: AttackProgress): void {
  switch (prog.phase) {
    case 'observe':
      appendBadge('  Encryption oracle queried on a zero block; keystream AESL(S0\u2295S2) captured (ct\u2295pt). \u2713',
                  '1 query', '2^130 data');
      break;

    case 'guess-determine':
      if (prog.step.startsWith('scan'))
        appendLog('  Testing candidates against the leak equation A(S0\u2295S2) \u2014 ' + prog.candidateCount +
                  ' still fail to satisfy it (each rejected on a byte mismatch, not merely "tried").');
      else if (prog.step.startsWith('unique'))
        appendLog('  One candidate satisfies the equation on all 16 bytes: its key reproduces the observed keystream exactly. \u2713', 'ok-text');
      break;

    case 'forge':
      appendLog('  Decryption oracle ACCEPTED a forgery signed with the recovered key ' +
                '(and rejected a random-tag forgery). \u2713', 'ok-text');
      break;

    case 'done':
      break;
  }
}

/* ------------------------------------------------------------------ */
/* Bridge demo — "Ask the oracle"                                      */
/* Makes the causal step tangible: in the ciphertext-only world a       */
/* candidate stays unconfirmable; with a decryption oracle the SAME     */
/* candidate is confirmed by a real accept. Uses the real toy crypto.   */
/* ------------------------------------------------------------------ */
const ocStdGuessEl   = $('oc-std-guess');
const ocStdVerdictEl = $('oc-std-verdict');
const ocStdRunBtnEl  = $('oc-std-run') as HTMLButtonElement;
const ocExtGuessEl   = $('oc-ext-guess');
const ocExtVerdictEl = $('oc-ext-verdict');
const ocRunBtnEl     = $('oc-run') as HTMLButtonElement;

/**
 * One candidate list, evaluated by both worlds.
 *
 * Both sides used to invent their own random seed, and the standard-model side
 * did nothing with its one: it spun for 900ms and printed a fixed
 * "? unresolvable — no oracle to ask". That is the conclusion asserted, which
 * is the one thing this panel exists to avoid, and it also meant the two
 * columns were never comparing the same candidate.
 *
 * Now a single list is drawn — one entry of which is the true key — and each
 * side runs the check that world genuinely permits:
 *
 *   Standard model: the attacker holds a ciphertext of an unknown plaintext.
 *     For each candidate it computes the plaintext that candidate implies,
 *     p_k = ct ⊕ keystream(k). Every candidate yields *a* plaintext, so no
 *     candidate can be excluded. The dead end is a counted result — 0 of N
 *     eliminated — not a spinner.
 *
 *   Extended model: the same candidates are submitted as real forgeries and
 *     the decryption oracle answers, eliminating N−1 and confirming one.
 */
interface OcCandidate {
  seed: number;
  label: string;
  key: Uint8Array;
  isTrue: boolean;
  /**
   * A control submission: the true key's own forgery with its tag randomised.
   * The oracle must reject it, which is what separates "the oracle judged this
   * submission" from "the page recognised the key" — without it, a verdict read
   * straight off the ground-truth flag would print exactly the same page.
   */
  corruptTag?: boolean;
}

let ocCandidates: OcCandidate[] | null = null;
let ocCiphertext: Uint8Array | null = null;

const OC_SECRET = new TextEncoder().encode('meet me at midnight');

function drawOcCandidates(): void {
  const bytes = new Uint8Array(2 * 6);
  crypto.getRandomValues(bytes);
  const seeds: number[] = [];
  for (let i = 0; i < 5; i++) {
    seeds.push(((bytes[2 * i] | (bytes[2 * i + 1] << 8)) & (TOY_SEED_SPACE - 1)) >>> 0);
  }
  const trueSeed = ((bytes[10] | (bytes[11] << 8)) & (TOY_SEED_SPACE - 1)) >>> 0;
  const all = seeds.filter((s) => s !== trueSeed).slice(0, 4);
  // Put the real key at a random position so the list order gives nothing away.
  const insertAt = Math.floor(Math.random() * (all.length + 1));
  all.splice(insertAt, 0, trueSeed);

  ocCandidates = all.map((seed) => ({
    seed,
    label: '0x' + seed.toString(16).padStart(4, '0'),
    key: deriveToyKey(seed),
    isTrue: seed === trueSeed,
  }));

  // The intercepted ciphertext: the true key encrypting a message the attacker
  // does not know. This is all a ciphertext-only attacker ever sees.
  const trueKey = deriveToyKey(trueSeed);
  ocCiphertext = encryptToyHiAE(trueKey, new Uint8Array(TOY_NONCE), OC_SECRET, new Uint8Array(TOY_AD))
    .ciphertext;

  const labels = ocCandidates.map((c) => c.label).join(', ');
  ocStdGuessEl.textContent = 'candidate keys: ' + labels;
  ocExtGuessEl.textContent = 'candidate keys: ' + labels;
}

function ensureOcCandidates(): void {
  if (!ocCandidates || !ocCiphertext) drawOcCandidates();
}

function renderOcList(target: HTMLElement, rows: { text: string; cls: string }[]): void {
  target.textContent = '';
  for (const row of rows) {
    const li = document.createElement('li');
    li.className = 'oc-item ' + row.cls;
    li.textContent = row.text;
    target.appendChild(li);
  }
}

function printableRatio(bytes: Uint8Array): number {
  let n = 0;
  for (const b of bytes) if (b === 0x0a || (b >= 0x20 && b < 0x7f)) n++;
  return n / bytes.length;
}

ocStdRunBtnEl.addEventListener('click', () => {
  ocStdRunBtnEl.disabled = true;
  try {
    ensureOcCandidates();
    const ct = ocCiphertext!.subarray(0, 16);
    let eliminated = 0;
    const rows = ocCandidates!.map((c) => {
      // The only computation available without an oracle: what plaintext would
      // this key imply for the ciphertext we intercepted?
      const ks = keystreamBlockOf(c.key);
      const implied = new Uint8Array(16);
      for (let i = 0; i < 16; i++) implied[i] = ct[i] ^ ks[i];
      // Nothing rules it out: the plaintext was never known, so any byte string
      // is a legal explanation. Count the eliminations honestly — there are none.
      const looksText = printableRatio(implied) > 0.9;
      return {
        text:
          c.label + ' implies plaintext ' + toHex(implied).slice(0, 16) + '\u2026' +
          (looksText ? ' (printable)' : '') + ' \u2014 consistent, cannot be excluded',
        cls: 'oc-item-unknown',
      };
    });
    renderOcList($('oc-std-list'), rows);
    ocStdVerdictEl.textContent =
      eliminated + ' of ' + ocCandidates!.length + ' candidates eliminated \u2014 the predicate is vacuous';
    ocStdVerdictEl.className = 'oc-verdict oc-unknown';
  } finally {
    ocStdRunBtnEl.disabled = false;
  }
});

ocRunBtnEl.addEventListener('click', async () => {
  ocRunBtnEl.disabled = true;
  try {
    ensureOcCandidates();
    const nonce = new Uint8Array(TOY_NONCE);
    const ad = new Uint8Array(TOY_AD);
    const trueKey = ocCandidates!.find((c) => c.isTrue)!.key;

    ocExtVerdictEl.textContent = '\u2026 submitting forgeries to the oracle';
    ocExtVerdictEl.className = 'oc-verdict oc-pending';
    if (!prefersReducedMotion) await sleep(400);

    const trueEntry = ocCandidates!.find((c) => c.isTrue)!;
    // The control rides in the same list and through the same code path, so it
    // is judged by whatever judges the candidates.
    const submissions: OcCandidate[] = [
      ...ocCandidates!,
      { ...trueEntry, label: trueEntry.label + ' (tag corrupted)', corruptTag: true },
    ];

    // Submit everything first, then read every number below off this one array,
    // so no line of the verdict can drift from what the oracle actually said.
    const results = submissions.map((c) => {
      // A real forgery from each candidate, judged by the real decryption
      // oracle keyed with the true key. A wrong candidate produces a tag the
      // oracle rejects; the right one produces a tag it accepts.
      const msg = new TextEncoder().encode('oracle-confirm');
      const forged = encryptToyHiAE(c.key, nonce, msg, ad);
      const tag = new Uint8Array(forged.tag);
      if (c.corruptTag) tag[0] ^= 0xff;
      const verdict = decryptOracle(trueKey, nonce, forged.ciphertext, ad, tag);
      return { c, valid: verdict.valid };
    });

    const accepted = results.filter((r) => r.valid);
    const eliminated = results.filter((r) => !r.valid && !r.c.corruptTag).length;
    const controlRejected = results.some((r) => r.c.corruptTag && !r.valid);

    renderOcList(
      $('oc-ext-list'),
      results.map((r) => ({
        text:
          r.c.label +
          (r.valid ? ' \u2713 ACCEPTED \u2014 confirmed' : ' \u2717 rejected \u2014 eliminated') +
          (r.c.corruptTag ? ' (control: right key, wrong tag)' : ''),
        cls: r.valid ? 'oc-item-accept' : 'oc-item-reject',
      })),
    );

    ocExtVerdictEl.textContent =
      eliminated + ' of ' + ocCandidates!.length + ' eliminated; ' +
      accepted.length + ' submission' + (accepted.length === 1 ? '' : 's') + ' ACCEPTED' +
      (accepted.length ? ' (' + accepted.map((r) => r.c.label).join(', ') + ')' : '') +
      '; control with a corrupted tag ' +
      (controlRejected ? 'rejected' : 'ACCEPTED \u2014 the oracle is not authenticating');
    ocExtVerdictEl.className = 'oc-verdict ' + (accepted.length ? 'oc-accept' : 'oc-reject');
  } finally {
    ocRunBtnEl.disabled = false;
  }
});

/* ------------------------------------------------------------------ */
/* Generate Instance                                                   */
/* ------------------------------------------------------------------ */
generateBtnEl.addEventListener('click', () => {
  // Draw a secret seed from the keyspace the learner disclosed, derive the key
  // from it. The attack must REDISCOVER this seed from oracle output \u2014 it is
  // never handed the key or the seed.
  const seedSpace = seedSpaceFor(Number(seedWidthEl.value));
  const seed = chooseSeed(seedSpace);
  const key = deriveToyKey(seed);

  instance = { seed, key, seedSpace, nonce: new Uint8Array(TOY_NONCE), ad: new Uint8Array(TOY_AD) };

  instanceMetaEl.textContent =
    'Toy instance generated. Secret seed drawn from the disclosed 2^' +
    Math.log2(seedSpace).toFixed(0) + ' keyspace (the KDF itself spans 2^' + TOY_SEED_BITS +
    '); key derived by the public toy KDF. Encryption oracle ready. ' +
    '(The attack does not get the seed or key.)';
  runBtnEl.disabled = false;
  retireAttackRun();
  kvStatusEl.textContent = 'Instance ready. Run the attack to watch each candidate get checked against the leak.';

  // The leak rows now belong to this instance: they are the block phase 1 will
  // capture, so a learner can check the attack's observed leak against them.
  renderLeakExplainer(
    key,
    'These rows are the live instance\u2019s own leak \u2014 the exact block the attack captures below. ' +
      'The seed stays secret; the keystream does not, which is the leak.',
  );
});

/* ------------------------------------------------------------------ */
/* Run Attack                                                          */
/* ------------------------------------------------------------------ */
runBtnEl.addEventListener('click', async () => {
  if (!instance) return;
  const cur = instance;

  runBtnEl.disabled = true;
  generateBtnEl.disabled = true;
  runBtnEl.textContent = 'Running…';
  attackLogEl.setAttribute('aria-busy', 'true');
  attackLogEl.innerHTML = '';
  disclaimerEl.classList.add('hidden');
  forgeResultEl.classList.add('hidden');

  // Panel A: drive the state grid from the real update path so the animation
  // shows the scheme mutating while the attack runs.
  animateUpdatePath();

  const encOracle = async (pt: Uint8Array) => {
    const out = encryptToyHiAE(cur.key, cur.nonce, pt, cur.ad);
    return { ct: out.ciphertext, tag: out.tag };
  };

  // Under a standard-model scenario there is no oracle object at all, not a
  // disabled one: the attack is handed null and cannot query what does not exist.
  const decOracleFn = oracleExposed()
    ? async (ct: Uint8Array, tag: Uint8Array) => {
        const out = decryptOracle(cur.key, cur.nonce, ct, cur.ad, tag);
        return { valid: out.valid, pt: out.plaintext };
      }
    : null;

  try {
    const start = performance.now();

    appendLog('\u25B6 Phase 1: Observe \u2014 capture keystream from the encryption oracle', 'phase-header');
    const result = await runModelBreachAttack(
      encOracle,
      decOracleFn,
      (p: AttackProgress) => {
        if (p.phase === 'guess-determine' && p.step === 'scan-0')
          appendLog('\u25B6 Phase 2: Guess-and-determine over the disclosed toy keyspace', 'phase-header');
        if (p.phase === 'forge')
          appendLog(
            p.step === 'no-oracle'
              ? '\u25B6 Phase 3: Forge \u2014 BLOCKED, this deployment exposes no decryption oracle'
              : '\u25B6 Phase 3: Forge \u2014 confirm the recovered key against the decryption oracle',
            'phase-header',
          );
        renderProgress(p);
      },
      {
        nonce: cur.nonce,
        ad: cur.ad,
        encryptLocal: (k, n, pt, ad) => encryptToyHiAE(k, n, pt, ad),
        seedSpace: cur.seedSpace,
      },
    );

    const elapsed = Math.round(performance.now() - start);

    // Visualize the equation check: the leak A(S0\u2295S2) the oracle exposed, then
    // decoy candidates failing it byte-by-byte and the recovered one satisfying
    // it. All keystreams here are recomputed live from the recovered seed's key.
    const observedLeak = keystreamBlockOf(cur.key);
    await animateEquationCheck(observedLeak, result.recoveredSeed, result.seedSpace);

    appendLog('');
    appendLog('\u25B6 KEY RECOVERED', 'phase-header result-header');
    const expHex = toHex(cur.key);
    const recHex = toHex(result.recoveredKey);
    const match = expHex === recHex;
    appendLog('  Recovered seed: 0x' + result.recoveredSeed.toString(16).padStart(4, '0') +
              ' (rediscovered from oracle output, not read from the instance)');
    appendLog('  Recovered key:  ' + recHex.slice(0, 16) + '\u2026 (32 bytes)');
    appendLog('  Candidates tested: ' + result.candidatesTested.toLocaleString('en-US') + ' of ' +
              result.seedSpace.toLocaleString('en-US') + ' (2^' +
              Math.log2(result.seedSpace).toFixed(0) + ' disclosed keyspace)');
    appendLog('  Verification vs instance ground truth: ' + (match ? '\u2713 EXACT MATCH' : '\u2717 MISMATCH'),
              match ? 'ok-text' : 'danger-text');
    if (!result.oracleAvailable) {
      // Be explicit about who knows what. The line above is this page checking
      // its own answer; the attacker in this deployment cannot run that check.
      appendLog(
        '  \u26A0 That match is checked by this page, which knows the seed. The attacker in Scenario ' +
        activeScenario.toUpperCase() + ' cannot run it: with no decryption oracle there is no predicate ' +
        'to evaluate a candidate against, so the key is recovered and unconfirmable at the same time.',
        'log-note',
      );
    }
    appendLog('  Total time: ' + elapsed + 'ms');
    appendLog(
      '  Note: this recovers the toy key by searching the disclosed 2^' +
      Math.log2(result.seedSpace).toFixed(0) +
      ' keyspace against real oracle output. Full-scale recovery of a random 256-bit HiAE key ' +
      '(2^209 time, 2^130 data, ePrint 2025/1203) is annotated, never executed in-browser.',
      'log-note',
    );

    recordRun({
      seedSpace: result.seedSpace,
      seed: result.recoveredSeed,
      tested: result.candidatesTested,
      ms: elapsed,
      confirmed: result.forgeConfirmed,
      oracleAvailable: result.oracleAvailable,
    });

    if (result.forgeConfirmed) forgeResultEl.classList.remove('hidden');
    disclaimerEl.classList.remove('hidden');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    appendLog('Attack failed: ' + msg, 'danger-text');
  } finally {
    runBtnEl.disabled = false;
    generateBtnEl.disabled = false;
    runBtnEl.textContent = 'Run Attack';
    attackLogEl.setAttribute('aria-busy', 'false');
  }
});
