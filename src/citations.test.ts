import { describe, expect, it } from 'vitest';
import pageSource from './main.ts?raw';
import readmeSource from '../README.md?raw';

/**
 * Citation gate. Every sentence this lab puts in quotation marks has to be a
 * character-for-character span of the record it is attributed to, and every
 * author list has to belong to the version being cited. Panel D once carried
 * two lines that failed that: the opening of 2025/1235's *title* presented as a
 * body quotation, and "The attack operates outside Section 4.5 of our paper."
 * — a sentence in neither abstract. These assertions pin the sourced text so
 * neither can return unnoticed.
 *
 * Sources, re-read before each string below was inserted:
 *  - local OAI harvest of 14 November 2026 — 2025/1235 (datestamp 2025-07-09)
 *    and 2025/1203 (datestamp 2026-04-16, the current sole-author revision),
 *  - IACR News item 26111, 30 June 2025 — the first, seven-author version of
 *    2025/1203, which the OAI record no longer exposes.
 */

/** Panel text as it ships: the page is a template literal, so \uXXXX is the source form. */
const pageText = pageSource
  .replace(/\\u([0-9a-fA-F]{4})/g, (_full: string, hex: string) =>
    String.fromCharCode(parseInt(hex, 16)),
  )
  .replace(/<[^>]+>/g, ' ')
  .replace(/\s+/g, ' ');

const readme = readmeSource.replace(/\s+/g, ' ');

describe('Quoted text belongs to the record it is attributed to', () => {
  it('gives 2025/1235 its own title, its authors, and one line from its abstract', () => {
    expect(pageText).toContain(
      'HiAE Remains Secure in Its Intended Model: A Clarification of Claimed Attacks',
    );
    expect(pageText).toContain('Han Chen, Tao Huang, Phuong Pham, Shuang Wu');
    expect(pageText).toContain(
      'In this note, we clarify that the claimed attacks rely critically on submitting ' +
        'forged-tag decryption queries — a type of behavior explicitly excluded by ' +
        'HiAE’s original security model.',
    );
  });

  it('quotes no sentence that no abstract contains', () => {
    expect(pageText).not.toContain('Section 4.5');
    // A title is a title: it is not a sentence the designers wrote in the body.
    expect(pageText).not.toContain('HiAE remains secure in its intended model.');
  });

  it('cites 2025/1203 by version — seven authors first, Xichao Hu alone in the revision', () => {
    expect(pageText).toContain(
      'Xichao Hu, Lin Jiao, Dengguo Feng, Yonglin Hao, Senpeng Wang, Yongqiang Li, Xinxin Gong',
    );
    expect(pageText).toContain('Breaking The Authenticated Encryption scheme HiAE');
    expect(pageText).toContain('16 April 2026 revision, which lists Xichao Hu alone');
    expect(pageText).toContain(
      'Analyze the Security of the AEAD Scheme HiAE by Algebraic Techniques',
    );
  });

  it('records which framing the revision withdrew, quoting both versions', () => {
    expect(pageText).toContain('IACR News item 26111');
    // The page's own sentence, not only the spans it quotes.
    expect(pageText).toContain('own framing moved while its arithmetic did not');
    expect(pageText).toContain('clarification answers that first version');
    expect(pageText).toContain('the first full key-recovery attack on HiAE');
    expect(pageText).toContain(
      'breaking the claimed 256-bit security against key-recovery attacks',
    );
    expect(pageText).toContain(
      "considers a stronger scenario than HiAE's original security model, and thus does " +
        'not invalidate its original security claims.',
    );
  });

  it('README cites the same versions, authors and dates as the page', () => {
    expect(readme).toContain('ePrint 2025/1203 (Xichao Hu, revised 16 April 2026');
    expect(readme).toContain(
      'Xichao Hu, Lin Jiao, Dengguo Feng, Yonglin Hao, Senpeng Wang, Yongqiang Li, Xinxin Gong',
    );
    expect(readme).toContain('Han Chen, Tao Huang, Phuong Pham, Shuang Wu');
    expect(readme).toContain('IACR News item 26111');
    expect(readme).not.toMatch(/Hu et al/);
    // The sole-author list belongs to the revision, not to the June 2025 posting.
    expect(readme).not.toMatch(/2025\/1203 \(Xichao Hu, June 2025/);
  });
});
