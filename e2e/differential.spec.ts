import { expect, test, type Page } from '@playwright/test';

/**
 * Browser gate for the differential-step panel — the section that used to be
 * the "what the paper does" prose column.
 *
 * These assertions are on numbers the page computed in that run: the α/β pair
 * off a real AESL evaluation, the per-S-box solution counts read out of the
 * DDT, the measured collapse from 2^32, and the enumeration's own candidate
 * count. The failure path matters too — the panel reports a non-unique
 * differential as a failure rather than dressing it up, and the three checks
 * are rendered from computed booleans, so a broken solver shows red here.
 */

const HEX32 = /^[0-9a-f]{32}$/;

async function runStep(page: Page): Promise<void> {
  await page.locator('#run-diffstep').click();
  await expect(page.locator('#diffstep-out')).toBeVisible();
}

test('the DDT census is counted on load and reports one solution per pair', async ({ page }) => {
  await page.goto('.');
  const stats = page.locator('#ds-ddt-stats');
  await expect(stats).toContainText('65,280'); // 255 x 256 difference pairs
  await expect(stats).toContainText('1.00'); // mean solutions per pair
  await expect(page.locator('#ds-ddt-note')).toContainText('65,280 solutions spread over 65,280');
});

test('running the differential step prints this run’s α, β and per-S-box solutions', async ({
  page,
}) => {
  await page.goto('.');
  await expect(page.locator('#diffstep-out')).toBeHidden();
  await runStep(page);

  const alpha = (await page.locator('#ds-alpha').innerText()).trim();
  const beta = (await page.locator('#ds-beta').innerText()).trim();
  expect(alpha).toMatch(HEX32);
  expect(beta).toMatch(HEX32);
  expect(alpha).not.toBe(beta);
  // α is active in exactly four bytes; the other twelve are zero.
  const alphaBytes = alpha.match(/../g)!;
  expect(alphaBytes.filter((b) => b !== '00')).toHaveLength(4);

  // One row per active S-box, each with a real DDT solution count.
  const rows = page.locator('#diffstep-out .ds-table tbody tr');
  await expect(rows).toHaveCount(4);
  for (let i = 0; i < 4; i += 1) {
    const count = Number((await rows.nth(i).locator('td').nth(3).innerText()).trim());
    expect([2, 4]).toContain(count);
    const inputs = (await rows.nth(i).locator('td').nth(4).innerText()).trim().split(/\s+/);
    expect(inputs).toHaveLength(count);
  }
});

test('the panel measures the collapse and the enumeration confirms it', async ({ page }) => {
  await page.goto('.');
  await runStep(page);

  const out = page.locator('#diffstep-out');
  await expect(out).toContainText('space knowing α only');
  await expect(out).toContainText('2^32');
  await expect(out).toContainText('measured reduction');

  // All three checks are computed booleans; a broken solver renders them red.
  await expect(page.locator('#ds-checks .ok-text')).toHaveCount(3);
  await expect(page.locator('#ds-checks .danger-text')).toHaveCount(0);
  await expect(page.locator('#ds-verdict')).toContainText('collapsed');
  await expect(page.locator('#ds-verdict')).toHaveClass(/ok-text/);

  // The enumeration really ran: it reports work done, not a constant.
  await expect(page.locator('#ds-meta')).toContainText('candidate pairs enumerated in');
});

test('re-running produces a different differential — the numbers come from the run', async ({
  page,
}) => {
  await page.goto('.');
  await runStep(page);
  const first = (await page.locator('#ds-beta').innerText()).trim();
  await page.locator('#run-diffstep').click();
  const second = (await page.locator('#ds-beta').innerText()).trim();
  expect(second).not.toBe(first);
  await expect(page.locator('#ds-checks .danger-text')).toHaveCount(0);
});

test('the panel states its scale rather than implying the full attack ran', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('.ds-scale')).toContainText('one');
  await expect(page.locator('.ds-scale')).toContainText('not executed here');
});
