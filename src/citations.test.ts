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
 *  - local OAI harvest of 14 November 2026 — 2025/1235 (datestamp 2025-07-09),
 *    2025/1203 (datestamp 2026-04-16, the current sole-author revision) and
 *    2025/1180 (datestamp 2026-06-16),
 *  - IACR News item 26111, 30 June 2025 — the first, seven-author version of
 *    2025/1203, which the OAI record no longer exposes,
 *  - the 2025/1180 paper page itself, for the metadata the OAI record does not
 *    carry: "A minor revision of an IACR publication in TOSC 2026", DOI
 *    10.46586/tosc.ak5womx4wo3r. (The eprint.iacr.asia mirror still shows that
 *    record as "Preprint." with no DOI; it is stale on that field.)
 *
 * 2025/1180 was cited by a short title it does not have, "Cryptanalysis of
 * HiAE", and described as independent confirmation of the extended-oracle
 * result. Its abstract claims neither: it reports its own key recovery, and its
 * model is nonce-respecting and uses decryption queries. Both the title and the
 * two load-bearing model words are gated below.
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

  it('gives 2025/1180 its full title, both authors, and its abstract on data and time', () => {
    expect(pageText).toContain('Cryptanalysis of the Authenticated Stream Cipher HiAE');
    expect(pageText).toContain('Alexander Bille');
    expect(pageText).toContain('Elmar Tischhauser');
    // Tags collapse to spaces here, so the superscripts read "2 128" / "2 129".
    expect(pageText).toContain('a complexity of 2 128 data and at most 2 129 time');
    expect(pageText).toContain('a minor revision of an IACR publication in ToSC 2026');
  });

  it('keeps 2025/1180 in the model its abstract states, and claims no more for it', () => {
    expect(pageText).toContain(
      'Our attack model is nonce-respecting and uses decryption queries',
    );
    // The short title is not this paper's title.
    expect(pageText).not.toContain('Cryptanalysis of HiAE');
    // The abstract does not present the work as confirming Hu's result, and its
    // own model is nonce-respecting — not Hu's extended forged-tag oracle model.
    expect(pageText).not.toContain('independent confirmation');
    expect(pageText).not.toContain('under their oracle model');
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

    // 2025/1180 by its own title, both authors, and the two abstract spans.
    expect(readme).toContain('Alexander Bille & Elmar Tischhauser');
    expect(readme).toContain(
      '*Cryptanalysis of the Authenticated Stream Cipher HiAE*, ePrint 2025/1180',
    );
    expect(readme).toContain(
      '"with a complexity of 2^128 data and at most 2^129 time"',
    );
    expect(readme).toContain(
      '"Our attack model is nonce-respecting and uses decryption queries."',
    );
    expect(readme).not.toMatch(/Bille & Tischhauser, ePrint 2025\/1180/);
  });
});

describe('the toy scale is stated wherever the toy is described', () => {
  // src/hiae.ts holds exactly four 128-bit blocks; real HiAE keeps sixteen
  // (a 2048-bit state). The README said "four-block" in its opening summary
  // and again in the attack section, but the Live Demo paragraph described
  // "a structurally correct toy-scale HiAE" with no number, which is the one
  // place a reader skimming for the deployed link would land.
  it('every README description of the toy HiAE names its block count', () => {
    // Scoped to the sentences that DESCRIBE the toy — the ones claiming it is
    // "structurally correct" — rather than every back-reference to it.
    const descriptions = readmeSource
      .split('\n')
      .filter((line) => /structurally correct/i.test(line));
    expect(descriptions.length).toBeGreaterThan(1);
    for (const line of descriptions) {
      expect(line, `"${line.trim().slice(0, 80)}…" must name the block count`).toMatch(
        /four-block|4-block/,
      );
    }
    expect(readmeSource).not.toContain('a structurally correct toy-scale HiAE,');
  });

  it('says what real HiAE keeps, next to the toy scale', () => {
    expect(readmeSource).toContain('sixteen 128-bit state blocks');
  });
});
