import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PathGuard } from '../src/index.js';

/**
 * Build a throwaway sandbox tree under the system temp dir for each test.
 * Returning a bag of paths keeps the assertions readable and avoids leaking
 * fixture state between tests.
 */
function makeSandbox() {
  const base = mkdtempSync(join(tmpdir(), 'ptg-'));
  // Root the guard will protect.
  const root = join(base, 'root');
  mkdirSync(root, { recursive: true });
  writeFileSync(join(root, 'inside.txt'), 'ok');
  mkdirSync(join(root, 'sub'), { recursive: true });
  writeFileSync(join(root, 'sub', 'deep.txt'), 'ok');
  // A sibling outside root, used for escape attempts.
  const outside = join(base, 'outside');
  mkdirSync(outside, { recursive: true });
  writeFileSync(join(outside, 'secret.txt'), 'nope');
  return { base, root, outside };
}

/**
 * Symlinks are created with relative targets so the test fixtures survive being
 * moved (some CI runners put temp dirs in odd places). Use a helper so every
 * escape test uses the same convention.
 */
function makeSymlink(from, to) {
  symlinkSync(to, from, 'file');
}

function cleanup(base) {
  rmSync(base, { recursive: true, force: true });
}

// --- Constructor validation ---

test('constructor rejects a relative root', () => {
  assert.throws(
    () => new PathGuard('relative/path'),
    /must be absolute/i,
  );
});

test('constructor rejects backslash separators in root', () => {
  assert.throws(
    () => new PathGuard('C:\\windows\\style'),
    /posix/i,
  );
});

test('constructor rejects a non-existent root', () => {
  const base = mkdtempSync(join(tmpdir(), 'ptg-ne-'));
  try {
    assert.throws(
      () => new PathGuard(join(base, 'does-not-exist')),
      { code: 'ENOENT' },
    );
  } finally {
    cleanup(base);
  }
});

// --- Happy path ---

test('a file directly inside root is safe', () => {
  const sb = makeSandbox();
  try {
    const g = new PathGuard(sb.root);
    const r = g.validate(join(sb.root, 'inside.txt'));
    assert.equal(r.safe, true);
    assert.equal(r.resolved, join(sb.root, 'inside.txt'));
  } finally {
    cleanup(sb.base);
  }
});

test('a file in a subdirectory of root is safe', () => {
  const sb = makeSandbox();
  try {
    const g = new PathGuard(sb.root);
    const r = g.validate(join(sb.root, 'sub', 'deep.txt'));
    assert.equal(r.safe, true);
  } finally {
    cleanup(sb.base);
  }
});

test('the root directory itself is safe', () => {
  const sb = makeSandbox();
  try {
    const g = new PathGuard(sb.root);
    assert.equal(g.isSafe(sb.root), true);
  } finally {
    cleanup(sb.base);
  }
});

// --- Dot-segment escapes ---

test('dot-dot escape past root is rejected', () => {
  const sb = makeSandbox();
  try {
    const g = new PathGuard(sb.root);
    const r = g.validate(join(sb.root, '..', 'outside', 'secret.txt'));
    assert.equal(r.safe, false);
    // Resolved path must genuinely point outside root.
    assert.equal(r.resolved, join(sb.outside, 'secret.txt'));
  } finally {
    cleanup(sb.base);
  }
});

test('dot-dot segments that stay inside root are safe', () => {
  const sb = makeSandbox();
  try {
    const g = new PathGuard(sb.root);
    // root/sub/../inside.txt collapses to root/inside.txt — still inside.
    const r = g.validate(join(sb.root, 'sub', '..', 'inside.txt'));
    assert.equal(r.safe, true);
    assert.equal(r.resolved, join(sb.root, 'inside.txt'));
  } finally {
    cleanup(sb.base);
  }
});

test('prefix-confusion sibling is rejected (root=/a/b vs /a/bx)', () => {
  const sb = makeSandbox();
  try {
    // Make a sibling whose name extends root's name.
    const sibling = `${sb.root}x`;
    mkdirSync(sibling);
    writeFileSync(join(sibling, 'trap.txt'), 'nope');
    const g = new PathGuard(sb.root);
    const r = g.validate(join(sibling, 'trap.txt'));
    assert.equal(r.safe, false);
  } finally {
    cleanup(sb.base);
  }
});

// --- Symlink escapes ---

test('symlink pointing outside root is rejected', () => {
  const sb = makeSandbox();
  try {
    // Create a symlink inside root pointing at the outside directory.
    const link = join(sb.root, 'escape-link');
    makeSymlink(link, sb.outside);
    const g = new PathGuard(sb.root);
    const r = g.validate(join(sb.root, 'escape-link', 'secret.txt'));
    assert.equal(r.safe, false);
    // The resolved path follows the symlink to the real outside location.
    assert.equal(r.resolved, join(sb.outside, 'secret.txt'));
  } finally {
    cleanup(sb.base);
  }
});

test('symlink pointing inside root is safe', () => {
  const sb = makeSandbox();
  try {
    const link = join(sb.root, 'ok-link');
    makeSymlink(link, join(sb.root, 'inside.txt'));
    const g = new PathGuard(sb.root);
    const r = g.validate(link);
    assert.equal(r.safe, true);
  } finally {
    cleanup(sb.base);
  }
});

test('root that is itself a symlink is resolved before comparison', () => {
  const sb = makeSandbox();
  try {
    // Make /.../link-to-root -> /.../root, then guard the link.
    const linkToRoot = join(sb.base, 'link-to-root');
    makeSymlink(linkToRoot, sb.root);
    const g = new PathGuard(linkToRoot);
    // A file inside the real root should be considered safe when addressed via
    // the symlinked root, because we compare against the resolved root.
    assert.equal(g.isSafe(join(sb.root, 'inside.txt')), true);
    // And the guard's reported root is the resolved (real) root, not the link.
    assert.equal(g.root, sb.root);
  } finally {
    cleanup(sb.base);
  }
});

// --- Non-existent target paths ---

test('non-existent file under existing root directory is safe', () => {
  const sb = makeSandbox();
  try {
    const g = new PathGuard(sb.root);
    const r = g.validate(join(sb.root, 'does-not-exist-yet.txt'));
    assert.equal(r.safe, true);
  } finally {
    cleanup(sb.base);
  }
});

test('non-existent file whose existing ancestor escapes root is rejected', () => {
  const sb = makeSandbox();
  try {
    // root/escape-link -> outside, then ask about a non-existent child of it.
    const link = join(sb.root, 'escape-link');
    makeSymlink(link, sb.outside);
    const g = new PathGuard(sb.root);
    const r = g.validate(join(sb.root, 'escape-link', 'not-created.txt'));
    assert.equal(r.safe, false);
  } finally {
    cleanup(sb.base);
  }
});

// --- Input validation ---

test('validate rejects a relative target', () => {
  const sb = makeSandbox();
  try {
    const g = new PathGuard(sb.root);
    assert.throws(
      () => g.validate('relative/path'),
      /must be absolute/i,
    );
  } finally {
    cleanup(sb.base);
  }
});

test('validate rejects backslash separators', () => {
  const sb = makeSandbox();
  try {
    const g = new PathGuard(sb.root);
    assert.throws(
      () => g.validate(`${sb.root}\\inside.txt`),
      /posix/i,
    );
  } finally {
    cleanup(sb.base);
  }
});
