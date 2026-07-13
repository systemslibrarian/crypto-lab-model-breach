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
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/**
 * Neutralize animations/transitions/opacity. A mid-fade opacity (or a pulsing
 * cell) produces phantom contrast failures, so freeze everything to its final
 * visible state before scanning.
 */
async function freeze(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*, *::before, *::after {
      animation: none !important;
      transition: none !important;
      opacity: 1 !important;
    }`,
  });
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

async function scan(page: Page): Promise<void> {
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
    await freeze(page);
    await revealAll(page);
    await scan(page);
  }
}

/**
 * Run the live attack so the equation-check byte grid (match/miss cells), the
 * forge accept/reject cards, and the oracle-bridge accept badge are all
 * populated with real state, then scan that fully-realised view. This is what
 * contrast-gates the new coloured cues in BOTH themes.
 */
async function scanAfterAttack(page: Page): Promise<void> {
  await page.locator('#oc-run').click();
  await expect(page.locator('#oc-ext-verdict')).toContainText('ACCEPTED', { timeout: 15000 });
  await page.locator('#generate-instance').click();
  await page.locator('#run-attack').click();
  await expect(page.locator('#forge-result')).toBeVisible({ timeout: 25000 });
  await expect(page.locator('#kv-candidate .kv-byte.kv-match')).toHaveCount(16);
  await freeze(page);
  await revealAll(page);
  await scan(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await freeze(page);
  await revealAll(page);
  await scanAllScenarios(page);
  await scanAfterAttack(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await freeze(page);
  await revealAll(page);
  await scanAllScenarios(page);
  await scanAfterAttack(page);
});
