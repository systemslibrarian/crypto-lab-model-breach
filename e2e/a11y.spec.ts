import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the NIST KAT / theorem
 * vectors; this gates them on accessibility the same way. Scans the full page
 * with every collapsible/hidden region revealed, in both themes.
 *
 * This page has no <details>; its collapsibles are class-toggled:
 *  - the disclaimer aside (.disclaimer.hidden) is revealed only after an attack
 *    run — we drop the .hidden class to expose its text,
 *  - the scenario tabs (role="tab" / role="tabpanel") swap the panel text — we
 *    iterate every tab so each variant is scanned.
 *
 * Selecting a scenario now also decides whether the attack is handed a
 * decryption oracle, so the confirmed-forgery view and the blocked-forgery view
 * are two genuinely different pages and both are scanned.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];
const RUN_TIMEOUT = 25_000;

/**
 * Settle motion through the media query the page itself reads, rather than by
 * injecting test-only CSS. `prefersReducedMotion` in main.ts short-circuits the
 * JS-driven state-grid animation and the artificial sleeps, so this removes the
 * phantom mid-fade contrast readings the old blanket `transition: none`
 * override papered over, and makes the runs deterministic besides. It is
 * applied per test because `test.use({ reducedMotion })` did not reach the
 * context reliably on this Playwright version; the assertion below makes a
 * silent no-op impossible.
 */
async function openLab(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  const reduced = await page.evaluate(
    () => window.matchMedia('(prefers-reduced-motion: reduce)').matches,
  );
  expect(reduced, 'reduced-motion emulation did not take effect').toBe(true);
}

/** Reveal every class-toggled hidden region so axe can see it. */
async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const el of document.querySelectorAll('.hidden')) {
      el.classList.remove('hidden');
    }
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.removeAttribute('hidden');
    }
  });
}

/**
 * Wait until nothing is animating before axe reads colours. A scan that samples
 * mid-transition reads colour pairs the page never settles on — exactly the
 * phantom failure the old injection was hiding, and hiding it also meant the
 * suite could never observe a real transition defect.
 */
async function settle(page: Page): Promise<void> {
  await page.evaluate(
    () => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))),
  );
  await expect
    .poll(() => page.evaluate(() => document.getAnimations().length), { timeout: 10_000 })
    .toBe(0);
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(resolve)));
}

async function scan(page: Page): Promise<void> {
  await revealAll(page);
  await settle(page);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

/** Scan the page with each scenario tab selected in turn, then the base view. */
async function scanAllScenarios(page: Page): Promise<void> {
  await scan(page);
  const tabs = page.locator('[role="tab"]');
  const count = await tabs.count();
  for (let i = 0; i < count; i++) {
    await tabs.nth(i).click();
    await scan(page);
  }
}

/** Drive the bridge panel so both candidate lists are populated. */
async function runBridge(page: Page): Promise<void> {
  await page.locator('#oc-std-run').click();
  await expect(page.locator('#oc-std-verdict')).toContainText('vacuous');
  await page.locator('#oc-run').click();
  await expect(page.locator('#oc-ext-verdict')).toContainText('ACCEPTED', {
    timeout: RUN_TIMEOUT,
  });
}

/**
 * Run the live attack so the equation-check byte grid (match/miss cells), the
 * forge accept/reject cards, the run table and the bridge's candidate lists are
 * all populated with real state, then scan that fully-realised view. This is
 * what contrast-gates the coloured cues in BOTH themes.
 */
async function scanAfterAttack(page: Page, scenario: 'a' | 'b'): Promise<void> {
  // The differential-step panel renders its table, stat tiles and check lines
  // only after it runs, so drive it before scanning.
  await page.locator('#run-diffstep').click();
  await expect(page.locator('#ds-verdict')).toBeVisible({ timeout: 15_000 });
  await runBridge(page);

  await page.locator(`[data-scenario="${scenario}"]`).click();
  await page.locator('#seed-width').selectOption('12');
  await page.locator('#generate-instance').click();
  await page.locator('#run-attack').click();
  await expect(page.locator('#run-table-body tr')).toHaveCount(1, { timeout: RUN_TIMEOUT });
  await expect(page.locator('#kv-candidate .kv-byte.kv-match')).toHaveCount(16);
  if (scenario === 'b') {
    await expect(page.locator('#forge-result')).toBeVisible();
  } else {
    // Scenario A blocks phase 3, so the forge card must stay down.
    await expect(page.locator('#forge-result')).toBeHidden();
    await expect(page.locator('#attack-log')).toContainText('BLOCKED');
  }
  await scan(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  test.setTimeout(120_000);
  await openLab(page);
  await scanAllScenarios(page);
  await scanAfterAttack(page, 'b');
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  test.setTimeout(120_000);
  await openLab(page);
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await scanAllScenarios(page);
  await scanAfterAttack(page, 'b');
});

test('no WCAG A/AA violations with the forge phase blocked (dark)', async ({ page }) => {
  test.setTimeout(120_000);
  await openLab(page);
  await scanAfterAttack(page, 'a');
});

test('no WCAG A/AA violations with the forge phase blocked (light)', async ({ page }) => {
  test.setTimeout(120_000);
  await openLab(page);
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await scanAfterAttack(page, 'a');
});
