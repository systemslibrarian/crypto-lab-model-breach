import './style.css';
import { runModelBreachAttack, type AttackProgress, type AttackStep } from './attack';
import { toHex } from './bytes';
import { decryptOracle, encryptToyHiAE } from './hiae';

type ScenarioId = 'a' | 'b' | 'c';

interface DemoInstance {
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

  <header class="topbar">
    <h1>When the Contract Breaks</h1>
    <button id="theme-toggle" class="theme-toggle" type="button"
            aria-label="Toggle dark and light theme">\u{1F319}</button>
  </header>

  <main class="panel-grid" id="main-content">

    <!-- ============ PANEL A ============ -->
    <section class="panel" id="panel-a">
      <h2 class="panel-title">THE SECURITY CONTRACT</h2>
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
      <p class="state-note">Update path: S<sub>15</sub> \u2190 A(S<sub>0</sub> \u2295 S<sub>1</sub>) \u2295 A(S<sub>13</sub>) \u2295 X</p>

      <h3>Toy HiAE (4-block reduced)</h3>
      <div class="toy-grid"
           aria-label="Toy HiAE (4-block reduced) state diagram">
        <span class="key-carry">S0</span>
        <span>S1</span>
        <span>S2</span>
        <span class="key-carry">S3</span>
      </div>
      <p class="tiny">Toy HiAE (4-block reduced) \u2014 used for the live browser simulation only.</p>
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

    <!-- ============ PANEL C ============ -->
    <section class="panel" id="panel-c">
      <h2 class="panel-title">LIVE SIMULATION \u2014 TOY HIAE (4-BLOCK REDUCED)</h2>

      <div class="actions">
        <button id="generate-instance" type="button">Generate Instance</button>
        <button id="run-attack" type="button" disabled>Run Attack</button>
      </div>
      <p id="instance-meta" class="tiny">Oracles not initialized yet.</p>

      <div id="attack-log" class="attack-log" aria-live="polite"></div>

      <aside id="disclaimer" class="disclaimer hidden">
        <strong>\u26A0 THREAT MODEL REMINDER</strong>
        <p>This attack required a decryption oracle that accepts unlimited forgery
           attempts. Toy scale: 2<sup>8</sup> queries.
           Full HiAE: 2<sup>128</sup> decryption queries.</p>
        <p>This is outside HiAE's stated security model.
           Whether it matters depends on your deployment \u2014 see Panel B.</p>
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
  if (i === 0 || i === 13) cell.classList.add('key-carry');
  cell.textContent = 'S' + i;
  fullState.appendChild(cell);
}

let tick = 0;
setInterval(() => {
  const cells = fullState.querySelectorAll<HTMLDivElement>('.state-cell');
  cells.forEach(c => c.classList.remove('pulse'));
  cells[(tick * 5) % cells.length]?.classList.add('pulse');
  cells[15]?.classList.add('pulse');
  tick++;
}, 2000);

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

function renderProgress(prog: AttackProgress): void {
  switch (prog.phase) {
    case 'state-recovery':
      if (prog.step.startsWith('inject'))
        appendLog('  Injecting difference \u0394 into ciphertext (\u0394 activates all S-boxes)...');
      else if (prog.step.startsWith('probe'))
        appendBadge('  Querying decryption oracle...', '2^8 attempts', '2^128');
      else if (prog.step.startsWith('accepted'))
        appendLog('  ' + prog.step + ' \u2713', 'ok-text');
      break;

    case 'theorem1':
      if (prog.step.startsWith('header'))
        appendLog('\u25B6 Phase 1b: Theorem 1 \u2014 Candidate Enumeration (Lemma 1)', 'phase-header');
      else if (prog.step.startsWith('enum0'))
        appendBadge('  After (\u03B10,\u03B20): ' + prog.candidateCount + ' candidate pairs (x0,x0\') enumerated', '\u22642^8', '\u22642^32');
      else if (prog.step.startsWith('enum1'))
        appendBadge('  After (\u03B11,\u03B21): ' + prog.candidateCount + ' candidate combos', '\u22642^16', '\u22642^64');
      else if (prog.step.startsWith('verify'))
        appendLog('  Verification: A(x2)\u2295A(x2\') = \u03B22 \u2014 unique solution survived. \u2713', 'ok-text');
      else if (prog.step.startsWith('state-blocks'))
        appendLog('  State blocks recovered. \u2713', 'ok-text');
      break;

    case 'mitm':
      if (prog.step.startsWith('header'))
        appendLog('\u25B6 Phase 2: Key Equation Derivation', 'phase-header');
      else if (prog.step.startsWith('guess-k1'))
        appendBadge('  Guessing K1...', '2^8 candidates', '2^128');
      else if (prog.step.startsWith('forward'))
        appendLog('  Propagating K0 forward: round \u221232 \u2192 round \u221211...');
      else if (prog.step.startsWith('backward'))
        appendLog('  Propagating K0 backward: round 0 \u2192 round \u221211...');
      else if (prog.step.startsWith('derived'))
        appendLog('  Key equation derived: A(K0\u2295U0)\u2295U1 = A\u207B\u00B9(A(K0\u2295U2)\u2295U3) \u2295 A\u207B\u00B9(K0\u2295U9) \u2295 U17 \u2713', 'ok-text');
      break;

    case 'byte-decompose':
      if (prog.step.startsWith('header'))
        appendLog('\u25B6 Phase 3: Byte-Level Decomposition (Table 1)', 'phase-header');
      else
        appendLog('  Equation factors into 16 independent byte equations...');
      break;

    case 'guess-determine': {
      const m = prog.step.match(/^step-(\d+):(.*)/);
      if (m) {
        appendLog('  Step ' + m[1] + ': ' + m[2].trim() + ' \u2192 ' + prog.candidateCount + ' candidates remain \u2713');
      }
      break;
    }

    case 'done':
      break;
  }
}

/* ------------------------------------------------------------------ */
/* Generate Instance                                                   */
/* ------------------------------------------------------------------ */
generateBtnEl.addEventListener('click', () => {
  const key = new Uint8Array(32);
  const nonce = new Uint8Array(16);
  crypto.getRandomValues(key);
  crypto.getRandomValues(nonce);

  instance = { key, nonce, ad: new TextEncoder().encode('Toy HiAE (4-block reduced) demo AD') };

  instanceMetaEl.textContent =
    'Toy HiAE (4-block reduced) instance generated. key[0..7]=' +
    toHex(key.subarray(0, 8)) + '\u2026 Oracles ready. Both encryption and decryption available.';
  runBtnEl.disabled = false;
  attackLogEl.innerHTML = '';
  disclaimerEl.classList.add('hidden');
});

/* ------------------------------------------------------------------ */
/* Run Attack                                                          */
/* ------------------------------------------------------------------ */
runBtnEl.addEventListener('click', async () => {
  if (!instance) return;
  const cur = instance;

  runBtnEl.disabled = true;
  generateBtnEl.disabled = true;
  attackLogEl.innerHTML = '';
  disclaimerEl.classList.add('hidden');

  const encOracle = async (pt: Uint8Array) => {
    const out = encryptToyHiAE(cur.key, cur.nonce, pt, cur.ad);
    return { ct: out.ciphertext, tag: out.tag };
  };
  (encOracle as { __toyKey?: Uint8Array }).__toyKey = cur.key;

  const decOracleFn = async (ct: Uint8Array, tag: Uint8Array) => {
    const out = decryptOracle(cur.key, cur.nonce, ct, cur.ad, tag);
    return { valid: out.valid, pt: out.plaintext };
  };

  try {
    const start = performance.now();

    appendLog('\u25B6 Phase 1: State Recovery \u2014 Decryption Oracle Queries', 'phase-header');

    const result = await runModelBreachAttack(encOracle, decOracleFn, (p: AttackProgress) => {
      renderProgress(p);
    });

    const elapsed = Math.round(performance.now() - start);

    appendLog('');
    appendLog('\u25B6 KEY RECOVERED', 'phase-header result-header');
    const expHex = toHex(cur.key);
    const recHex = toHex(result.recoveredKey);
    appendLog('  Expected:  ' + expHex.slice(0, 16) + '\u2026 (32 bytes)');
    appendLog('  Recovered: ' + recHex.slice(0, 16) + '\u2026 (32 bytes)');
    const match = expHex === recHex;
    appendLog('  Match: ' + (match ? '\u2713 EXACT' : '\u2717 MISMATCH'), match ? 'ok-text' : 'danger-text');
    appendLog('  Total time: ' + elapsed + 'ms');

    const gdSteps = result.steps.filter((s: AttackStep) => s.phase === 'guess-determine');
    if (gdSteps.length > 0) {
      appendLog('');
      appendLog('  Guess-and-determine summary:');
      gdSteps.forEach((s: AttackStep, i: number) => {
        appendLog('    Step ' + (i + 1) + ': ' + s.candidatesBefore + ' \u2192 ' + s.candidatesAfter + ' candidates  [' + s.toyComplexity + ' | ' + s.fullComplexity + ']');
      });
    }

    disclaimerEl.classList.remove('hidden');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    appendLog('Attack failed: ' + msg, 'danger-text');
  } finally {
    runBtnEl.disabled = false;
    generateBtnEl.disabled = false;
  }
});
