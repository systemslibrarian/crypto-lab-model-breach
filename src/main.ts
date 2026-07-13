import './style.css';
import { runModelBreachAttack, type AttackProgress } from './attack';
import { toHex } from './bytes';
import { decryptOracle, encryptToyHiAE } from './hiae';
import { deriveToyKey, TOY_AD, TOY_NONCE, TOY_SEED_BITS, TOY_SEED_SPACE } from './toykey';

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
       The theme toggle stays in the DOM (main.ts wires it) but is hidden by the
       shared header CSS; it lives here so the lab's theme JS keeps working. -->
  <header class="cl-hero">
    <div class="cl-hero-main">
      <h1 class="cl-hero-title">Model Breach</h1>
      <p class="cl-hero-sub">Threat models as contracts · HiAE case study</p>
      <p class="cl-hero-desc">Walk a live case study where HiAE's 256-bit claim holds under its stated model, then watch it fall to 2<sup>209</sup> the moment an unlimited decryption oracle is added to the adversary.</p>
      <button id="theme-toggle" class="theme-toggle" type="button"
              aria-label="Toggle dark and light theme">\u{1F319}</button>
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
      <p class="state-note" id="state-note">Update path: S<sub>15</sub> \u2190 A(S<sub>0</sub> \u2295 S<sub>1</sub>) \u2295 A(S<sub>13</sub>) \u2295 X.
        <span class="state-note-live">On <strong>Run Attack</strong>, the cells feeding S<sub>15</sub>
        (S<sub>0</sub>, S<sub>1</sub>, S<sub>13</sub>) light up in sequence so you can watch the state actually mutate.</span></p>

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
        <div class="gap-bar" aria-hidden="true">
          <span class="mark left">HiAE claim</span>
          <span class="mark right">Attack model</span>
        </div>
        <p class="tiny">Threat model gap \u2014 the amber region is the territory the attack occupies.</p>
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
            <div class="oc-guess" id="oc-std-guess">candidate key: 0x????</div>
            <div class="oc-verdict oc-unknown" id="oc-std-verdict">? no way to check</div>
          </div>
        </div>
        <div class="oc-side oc-extended">
          <h3 class="oc-h">Extended model \u2014 decryption oracle</h3>
          <p class="tiny">The attacker submits a forgery built from each guess. A <strong>reject</strong> throws
            the candidate out; an <strong>accept</strong> confirms it. Guessing becomes searching.</p>
          <div class="oc-demo">
            <div class="oc-guess" id="oc-ext-guess">candidate key: 0x????</div>
            <div class="oc-verdict oc-pending" id="oc-ext-verdict" role="status" aria-live="polite">\u2014 idle</div>
          </div>
          <button id="oc-run" type="button" class="oc-btn">Ask the oracle</button>
        </div>
      </div>
      <p class="tiny oc-caption">Same candidate, two worlds. Only the world with an oracle lets a rejected
        forgery <em>eliminate</em> a candidate and an accepted one <em>confirm</em> it. Press the button to watch
        one candidate get confirmed by an oracle accept \u2014 the concrete meaning of "the model changed."</p>
    </section>

    <!-- ============ PANEL C ============ -->
    <section class="panel" id="panel-c">
      <h2 class="panel-title">LIVE SIMULATION \u2014 TOY HIAE (4-BLOCK REDUCED)</h2>

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

      <div class="actions">
        <button id="generate-instance" type="button">Generate Instance</button>
        <button id="run-attack" type="button" disabled>Run Attack</button>
      </div>
      <p id="instance-meta" class="tiny" role="status" aria-live="polite">Oracles not initialized yet.</p>

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
const themeToggleEl   = $('theme-toggle') as HTMLButtonElement;
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

/* ------------------------------------------------------------------ */
/* Scenario tabs                                                       */
/* ------------------------------------------------------------------ */
const scenarios: Record<ScenarioId, { text: string; cls: string }> = {
  a: {
    text: 'Scenario A: 6G base station \u2014 Attacker can observe traffic but cannot submit forgeries to the decryption pipeline. Standard model applies. HiAE is safe. \u2713',
    cls: 'ok',
  },
  b: {
    text: 'Scenario B: Shared API endpoint \u2014 Decryption is exposed as a service. Attacker can submit forged ciphertexts. Extended model applies. HiAE security falls to 2^209. \u26A0',
    cls: 'warn',
  },
  c: {
    text: 'Scenario C: GPU interconnect \u2014 Point-to-point hardware link. No decryption oracle exposure. Standard model applies. HiAE is safe. \u2713',
    cls: 'ok',
  },
};

function setScenario(id: ScenarioId): void {
  document.querySelectorAll<HTMLButtonElement>('[role="tab"]').forEach(tab => {
    const active = tab.dataset.scenario === id;
    tab.setAttribute('aria-selected', String(active));
    tab.classList.toggle('active', active);
    tab.setAttribute('tabindex', active ? '0' : '-1');
  });
  scenarioPanelEl.textContent = scenarios[id].text;
  scenarioPanelEl.className = 'scenario-card ' + scenarios[id].cls;
  scenarioPanelEl.setAttribute('aria-labelledby', 'tab-' + id);
}

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
/* Theme toggle                                                        */
/* ------------------------------------------------------------------ */
function syncThemeIcon(): void {
  const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
  themeToggleEl.textContent = isDark ? '\u{1F319}' : '\u2600\uFE0F';
}

themeToggleEl.addEventListener('click', () => {
  const cur = document.documentElement.getAttribute('data-theme') === 'light'
    ? 'light' : 'dark';
  const next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('cv-theme', next);
  syncThemeIcon();
});
syncThemeIcon();

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
function animateUpdatePath(): void {
  const cells = fullState.querySelectorAll<HTMLDivElement>('.state-cell');
  cells.forEach(c => c.classList.remove('pulse', 'update-src', 'update-dst'));
  const src = [0, 1, 13];

  if (prefersReducedMotion) {
    src.forEach(i => cells[i]?.classList.add('update-src'));
    cells[15]?.classList.add('update-dst');
    return;
  }

  let step = 0;
  const total = src.length + 1;
  const timer = window.setInterval(() => {
    if (step < src.length) {
      cells[src[step]]?.classList.add('update-src');
      cells[src[step]]?.classList.add('pulse');
    } else {
      cells[15]?.classList.add('update-dst');
      cells[15]?.classList.add('pulse');
    }
    step++;
    if (step >= total) {
      window.clearInterval(timer);
      window.setTimeout(() => {
        cells.forEach(c => c.classList.remove('pulse', 'update-src', 'update-dst'));
      }, 1600);
    }
  }, 550);
}

/* ------------------------------------------------------------------ */
/* Panel C \u2014 Attack helpers                                            */
/* ------------------------------------------------------------------ */
let instance: DemoInstance | null = null;

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
): Promise<void> {
  kvVizEl.setAttribute('aria-hidden', 'false');
  const obsCells = renderByteRow(kvObservedEl, observed);
  obsCells.forEach(c => c.classList.add('kv-observed'));

  const stepMs = prefersReducedMotion ? 0 : 260;

  // A handful of decoy seeds that are NOT the answer, to show the equation
  // rejecting wrong keys byte-by-byte.
  const decoys: number[] = [];
  for (let d = 1; d <= 3; d++) {
    const s = (correctSeed + d * 9973) & (TOY_SEED_SPACE - 1);
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
const ocExtGuessEl   = $('oc-ext-guess');
const ocExtVerdictEl = $('oc-ext-verdict');
const ocRunBtnEl     = $('oc-run') as HTMLButtonElement;

ocRunBtnEl.addEventListener('click', async () => {
  ocRunBtnEl.disabled = true;
  // Pick a real seed, derive its key, and build a genuine forgery from it.
  const seedBytes = new Uint8Array(2);
  crypto.getRandomValues(seedBytes);
  const seed = ((seedBytes[0] | (seedBytes[1] << 8)) & (TOY_SEED_SPACE - 1)) >>> 0;
  const label = '0x' + seed.toString(16).padStart(4, '0');
  const key = deriveToyKey(seed);
  const nonce = new Uint8Array(TOY_NONCE);
  const ad = new Uint8Array(TOY_AD);

  ocStdGuessEl.textContent = 'candidate key: ' + label;
  ocExtGuessEl.textContent = 'candidate key: ' + label;
  ocStdVerdictEl.textContent = '? still no way to check';
  ocStdVerdictEl.className = 'oc-verdict oc-unknown';
  ocExtVerdictEl.textContent = '… submitting forgery to oracle';
  ocExtVerdictEl.className = 'oc-verdict oc-pending';

  if (!prefersReducedMotion) await sleep(500);

  // Real forgery: encrypt a message with the candidate key, hand ct+tag to the
  // decryption oracle. A correct key produces a tag the oracle validates.
  const msg = new TextEncoder().encode('oracle-confirm');
  const forged = encryptToyHiAE(key, nonce, msg, ad);
  const verdict = decryptOracle(key, nonce, forged.ciphertext, ad, forged.tag);

  ocExtVerdictEl.textContent = verdict.valid
    ? '✓ ACCEPTED — candidate ' + label + ' confirmed'
    : '✗ rejected';
  ocExtVerdictEl.className = 'oc-verdict ' + (verdict.valid ? 'oc-accept' : 'oc-reject');
  ocRunBtnEl.disabled = false;
});

/* ------------------------------------------------------------------ */
/* Generate Instance                                                   */
/* ------------------------------------------------------------------ */
generateBtnEl.addEventListener('click', () => {
  // Draw a secret seed from the disclosed reduced toy keyspace, derive the key
  // from it. The attack must REDISCOVER this seed from oracle output \u2014 it is
  // never handed the key or the seed.
  const seedBytes = new Uint8Array(2);
  crypto.getRandomValues(seedBytes);
  const seed = ((seedBytes[0] | (seedBytes[1] << 8)) & (TOY_SEED_SPACE - 1)) >>> 0;
  const key = deriveToyKey(seed);

  instance = { seed, key, nonce: new Uint8Array(TOY_NONCE), ad: new Uint8Array(TOY_AD) };

  instanceMetaEl.textContent =
    'Toy instance generated. Secret seed drawn from the disclosed 2^' + TOY_SEED_BITS +
    ' keyspace; key derived by the public toy KDF. Encryption + decryption oracles ready. ' +
    '(The attack does not get the seed or key.)';
  runBtnEl.disabled = false;
  attackLogEl.innerHTML = '';
  disclaimerEl.classList.add('hidden');
  forgeResultEl.classList.add('hidden');
  kvVizEl.setAttribute('aria-hidden', 'true');
  kvObservedEl.textContent = '';
  kvCandidateEl.textContent = '';
  kvStatusEl.textContent = 'Instance ready. Run the attack to watch each candidate get checked against the leak.';
  kvStatusEl.className = 'kv-status';
  kvCandLabelEl.textContent = 'Candidate re-derives';
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

  const decOracleFn = async (ct: Uint8Array, tag: Uint8Array) => {
    const out = decryptOracle(cur.key, cur.nonce, ct, cur.ad, tag);
    return { valid: out.valid, pt: out.plaintext };
  };

  try {
    const start = performance.now();

    appendLog('\u25B6 Phase 1: Observe \u2014 capture keystream from the encryption oracle', 'phase-header');
    const result = await runModelBreachAttack(
      encOracle,
      decOracleFn,
      (p: AttackProgress) => {
        if (p.phase === 'guess-determine' && p.step === 'scan-0')
          appendLog('\u25B6 Phase 2: Guess-and-determine over the disclosed toy keyspace', 'phase-header');
        if (p.phase === 'forge' && p.step === 'accepted')
          appendLog('\u25B6 Phase 3: Forge \u2014 confirm the recovered key against the decryption oracle', 'phase-header');
        renderProgress(p);
      },
      {
        nonce: cur.nonce,
        ad: cur.ad,
        encryptLocal: (k, n, pt, ad) => encryptToyHiAE(k, n, pt, ad),
      },
    );

    const elapsed = Math.round(performance.now() - start);

    // Visualize the equation check: the leak A(S0\u2295S2) the oracle exposed, then
    // decoy candidates failing it byte-by-byte and the recovered one satisfying
    // it. All keystreams here are recomputed live from the recovered seed's key.
    const observedLeak = keystreamBlockOf(cur.key);
    await animateEquationCheck(observedLeak, result.recoveredSeed);

    appendLog('');
    appendLog('\u25B6 KEY RECOVERED', 'phase-header result-header');
    const expHex = toHex(cur.key);
    const recHex = toHex(result.recoveredKey);
    const match = expHex === recHex;
    appendLog('  Recovered seed: 0x' + result.recoveredSeed.toString(16).padStart(4, '0') +
              ' (rediscovered from oracle output, not read from the instance)');
    appendLog('  Recovered key:  ' + recHex.slice(0, 16) + '\u2026 (32 bytes)');
    appendLog('  Verification vs instance ground truth: ' + (match ? '\u2713 EXACT MATCH' : '\u2717 MISMATCH'),
              match ? 'ok-text' : 'danger-text');
    appendLog('  Total time: ' + elapsed + 'ms');
    appendLog(
      '  Note: this recovers the toy key by searching the disclosed 2^' + TOY_SEED_BITS +
      ' keyspace against real oracle output. Full-scale recovery of a random 256-bit HiAE key ' +
      '(2^209 time, 2^130 data, ePrint 2025/1203) is annotated, never executed in-browser.',
      'log-note',
    );

    forgeResultEl.classList.remove('hidden');
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
