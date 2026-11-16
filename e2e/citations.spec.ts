import { expect, test, type Page } from '@playwright/test';

/**
 * The academic record as the reader sees it. src/citations.test.ts pins the
 * source strings; this gate proves they survive the build and reach the DOM —
 * the page's quotation marks and em dashes are \uXXXX escapes in a template
 * literal, so "sourced in main.ts" and "rendered on the page" are two different
 * claims — and that the unsourced Section 4.5 line is gone from the whole page.
 */

async function openLab(page: Page): Promise<void> {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  await expect(page.locator('#panel-d')).toBeVisible();
}

test('the designers’ entry is their paper’s title plus a line from its abstract', async ({
  page,
}) => {
  await openLab(page);
  const record = page.locator('#panel-d');

  await expect(record).toContainText(
    'HiAE Remains Secure in Its Intended Model: A Clarification of Claimed Attacks',
  );
  await expect(record).toContainText('Han Chen, Tao Huang, Phuong Pham, Shuang Wu');
  await expect(record).toContainText(
    'we clarify that the claimed attacks rely critically on submitting forged-tag ' +
      'decryption queries — a type of behavior explicitly excluded by HiAE’s ' +
      'original security model.',
  );
});

test('nothing on the page is sourced to a section no abstract names', async ({ page }) => {
  await openLab(page);
  await expect(page.locator('body')).not.toContainText('Section 4.5');
});

test('2025/1203 is cited by version, and the revision is named with its date', async ({ page }) => {
  await openLab(page);
  const record = page.locator('#panel-d');

  await expect(record).toContainText(
    'Xichao Hu, Lin Jiao, Dengguo Feng, Yonglin Hao, Senpeng Wang, Yongqiang Li, Xinxin Gong',
  );
  await expect(record).toContainText('Breaking The Authenticated Encryption scheme HiAE');
  await expect(record).toContainText('16 April 2026 revision, which lists Xichao Hu alone');
});

test('the two positions are introduced with the framing the revision withdrew', async ({ page }) => {
  await openLab(page);
  // The note sits with the versioned comparison, where the attackers' and the
  // designers' positions are first set beside each other.
  const note = page.locator('#panel-b p', {
    hasText: 'own framing moved while its arithmetic did not',
  });

  await expect(note).toBeVisible();
  await expect(note).toContainText(
    'breaking the claimed 256-bit security against key-recovery attacks',
  );
  await expect(note).toContainText('does not invalidate its original security claims.');
  await expect(note.locator('a')).toHaveAttribute('href', 'https://iacr.org/news/item/26111');
});
