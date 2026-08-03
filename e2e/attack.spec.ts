import { expect, test, type Page } from '@playwright/test';

/**
 * Browser gate for the live simulation, the bridge panel and the scenario
 * contract — none of which had any e2e coverage: the whole suite was the
 * differential panel plus axe.
 *
 * Every assertion here reads a value the page computed in that run: the leak
 * bytes are compared against the leak the attack itself captured, the candidate
 * count is checked against the seed the learner placed, and the two sides of
 * the bridge are checked against each other on the same candidate list. The
 * failure paths are asserted beside the success paths: a deployment with no
 * decryption oracle must leave the forge card down and say why.
 */

const RUN_TIMEOUT = 30_000;

async function openLab(page: Page): Promise<void> {
  // Reduced motion removes the demo's artificial sleeps, so runs are quick and
  // deterministic without disabling anything the assertions depend on.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  await expect(page.locator('#generate-instance')).toBeVisible();
}

async function bytesOf(page: Page, selector: string): Promise<string[]> {
  return page.locator(`${selector} span`).allInnerTexts();
}

async function runAttack(page: Page): Promise<void> {
  await page.locator('#run-attack').click();
  await expect(page.locator('#run-table-body tr')).not.toHaveCount(0, { timeout: RUN_TIMEOUT });
}

test('the leak explainer shows the live instance, and it is the block the attack captures', async ({
  page,
}) => {
  await openLab(page);

  // Before an instance exists the rows are labelled as illustrative rather than
  // passed off as the target's. They used to be computed from a hardcoded
  // deriveToyKey(0x1a2b) with no relation to the instance at all, and nothing
  // on the page said so.
  await expect(page.locator('#leak-source')).toContainText('illustrative');
  const illustrative = await bytesOf(page, '#leak-ks');
  expect(illustrative).toHaveLength(16);

  await page.locator('#seed-width').selectOption('12');
  await page.locator('#generate-instance').click();
  await expect(page.locator('#leak-source')).toContainText('live instance');
  const live = await bytesOf(page, '#leak-ks');
  expect(live).toHaveLength(16);
  expect(live.join('')).not.toBe(illustrative.join(''));

  // The rows are internally consistent: ct of an all-zero block IS the keystream.
  expect(await bytesOf(page, '#leak-ct')).toEqual(live);
  expect((await bytesOf(page, '#leak-pt')).join('')).toBe('00'.repeat(16));

  // And they are the same 16 bytes phase 1 goes on to observe — the check that
  // the explainer is about the instance under attack rather than beside it.
  await runAttack(page);
  expect(await bytesOf(page, '#kv-observed')).toEqual(live);

  // A second instance moves them again, so no row outlives its instance.
  await page.locator('#generate-instance').click();
  const second = await bytesOf(page, '#leak-ks');
  expect(second.join('')).not.toBe(live.join(''));
});

test('the disclosed keyspace and the placed seed both move the measured cost', async ({ page }) => {
  test.setTimeout(90_000);
  await openLab(page);
  await page.locator('[data-scenario="b"]').click();

  // A seed the learner places is found after exactly seed+1 candidates: the
  // search starts at 0 and stops at the first key satisfying the leak equation.
  await page.locator('#seed-width').selectOption('8');
  await page.locator('#seed-choice').fill('5');
  await page.locator('#generate-instance').click();
  await runAttack(page);
  await expect(page.locator('#attack-log')).toContainText('Candidates tested: 6 of 256');
  await expect(page.locator('#run-table-body tr').first()).toContainText('2^8');
  await expect(page.locator('#run-table-body tr').first()).toContainText('6 of 256');
  await expect(page.locator('#run-table-body tr').first()).toContainText('0x0005');

  // Move the seed to the far end of the same space and the cost moves with it.
  await page.locator('#seed-choice').fill('200');
  await page.locator('#generate-instance').click();
  await runAttack(page);
  await expect(page.locator('#attack-log')).toContainText('Candidates tested: 201 of 256');

  // Widen the space and the same placed seed costs the same search but is now
  // one of far more keys — the disclosed keyspace is a real parameter, not a
  // constant printed in prose.
  await page.locator('#seed-width').selectOption('16');
  await page.locator('#seed-choice').fill('4096');
  await page.locator('#generate-instance').click();
  await expect(page.locator('#instance-meta')).toContainText('2^16 keyspace');
  await runAttack(page);
  await expect(page.locator('#attack-log')).toContainText('Candidates tested: 4,097 of 65,536');

  // Three completed runs, three measured rows.
  await expect(page.locator('#run-table-body tr')).toHaveCount(3);
});

test('a deployment with no decryption oracle blocks the forge phase and says so', async ({
  page,
}) => {
  test.setTimeout(90_000);
  await openLab(page);

  // Scenario A is the default and exposes no decryption pipeline.
  await expect(page.locator('[data-scenario="a"]')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#oracle-state')).toContainText('exposes no decryption oracle');

  await page.locator('#seed-width').selectOption('8');
  await page.locator('#seed-choice').fill('3');
  await page.locator('#generate-instance').click();
  await runAttack(page);

  // The key is still recovered — the keystream leak is an encryption-oracle
  // property — but nothing confirms it, and the page says which of those two
  // things happened rather than printing "forgery ACCEPTED" under a tab that
  // says no forgery can be submitted.
  const log = page.locator('#attack-log');
  await expect(log).toContainText('Candidates tested: 4 of 256');
  await expect(log).toContainText('BLOCKED');
  await expect(log).toContainText('no decryption oracle');
  await expect(log).toContainText('recovered and unconfirmable');
  await expect(page.locator('#forge-result')).toBeHidden();
  await expect(page.locator('#run-table-body tr').first()).toContainText('no oracle to ask');

  // The same instance under a deployment that does expose one reaches the
  // confirmed forgery. Same code, same seed, different threat model.
  await page.locator('[data-scenario="b"]').click();
  await expect(page.locator('#oracle-state')).toContainText('exposes a decryption oracle');
  // Switching deployments retires the run that described the previous one.
  await expect(log).toBeEmpty();
  await expect(page.locator('#forge-result')).toBeHidden();

  await page.locator('#generate-instance').click();
  await runAttack(page);
  await expect(log).toContainText('Decryption oracle ACCEPTED');
  await expect(log).not.toContainText('BLOCKED');
  await expect(page.locator('#forge-result')).toBeVisible();

  // Scenario C is the other standard-model deployment and behaves like A.
  await page.locator('[data-scenario="c"]').click();
  await expect(page.locator('#oracle-state')).toContainText('exposes no decryption oracle');
  await page.locator('#generate-instance').click();
  await runAttack(page);
  await expect(log).toContainText('BLOCKED');
  await expect(page.locator('#forge-result')).toBeHidden();
});

test('the standard-model side eliminates nothing, and it is a count rather than a caption', async ({
  page,
}) => {
  await openLab(page);

  await page.locator('#oc-std-run').click();
  const stdRows = page.locator('#oc-std-list .oc-item');
  await expect(stdRows).toHaveCount(5);
  // Every candidate implies *a* plaintext, so none can be excluded. The verdict
  // states the count it measured, and every row agrees with it.
  await expect(page.locator('#oc-std-verdict')).toHaveText(
    '0 of 5 candidates eliminated — the predicate is vacuous',
  );
  for (let i = 0; i < 5; i++) {
    await expect(stdRows.nth(i)).toContainText('cannot be excluded');
    await expect(stdRows.nth(i)).toContainText('implies plaintext');
  }

  // The extended side judges the SAME list — the panel's claim is "same
  // candidates, two worlds", and both columns print the list so it is checkable.
  const stdLabels = (await page.locator('#oc-std-guess').innerText()).trim();
  await page.locator('#oc-run').click();
  // Five candidates plus one control submission.
  await expect(page.locator('#oc-ext-list .oc-item')).toHaveCount(6, { timeout: RUN_TIMEOUT });
  expect((await page.locator('#oc-ext-guess').innerText()).trim()).toBe(stdLabels);

  // Four eliminated, one confirmed — by the real oracle, not by a label. The
  // control proves that: it carries the *correct* key with a corrupted tag, so
  // anything reading the answer off the candidate rather than off the oracle's
  // reply would accept two submissions here instead of one.
  await expect(page.locator('#oc-ext-verdict')).toContainText('4 of 5 eliminated');
  await expect(page.locator('#oc-ext-verdict')).toContainText('1 submission ACCEPTED');
  await expect(page.locator('#oc-ext-verdict')).toContainText('control with a corrupted tag rejected');
  await expect(page.locator('#oc-ext-verdict')).not.toContainText('not authenticating');
  await expect(page.locator('#oc-ext-list .oc-item-accept')).toHaveCount(1);
  await expect(page.locator('#oc-ext-list .oc-item-reject')).toHaveCount(5);
  const control = page.locator('#oc-ext-list .oc-item', { hasText: 'tag corrupted' });
  await expect(control).toHaveCount(1);
  await expect(control).toHaveClass(/oc-item-reject/);
  await expect(control).toContainText('right key, wrong tag');

  // The accepted candidate is one of the candidates that the left side could
  // not rule out: the oracle is what turned an unusable list into an answer.
  const accepted = (await page.locator('#oc-ext-list .oc-item-accept').innerText()).slice(0, 6);
  expect(stdLabels).toContain(accepted);
});

/**
 * The `[hidden]` override trap: the UA rule `[hidden] { display: none }` loses
 * to any author rule setting a display on the same element, so a panel shipping
 * the attribute renders anyway and every `el.hidden = true` is a silent no-op.
 */
test('no element carrying the hidden attribute is actually rendered', async ({ page }) => {
  await openLab(page);

  const leaks = async (): Promise<unknown[]> =>
    page.evaluate(() =>
      Array.from(document.querySelectorAll('[hidden]'))
        .filter((el) => getComputedStyle(el as HTMLElement).display !== 'none')
        .map((el) => ({
          tag: (el as HTMLElement).tagName.toLowerCase(),
          id: (el as HTMLElement).id,
          cls: (el as HTMLElement).className?.toString().slice(0, 60) ?? '',
        })),
    );

  expect(await leaks()).toEqual([]);
  await page.locator('#seed-width').selectOption('8');
  await page.locator('#generate-instance').click();
  await runAttack(page);
  expect(await leaks()).toEqual([]);
  await page.locator('#run-diffstep').click();
  await expect(page.locator('#diffstep-out')).toBeVisible();
  expect(await leaks()).toEqual([]);
});
