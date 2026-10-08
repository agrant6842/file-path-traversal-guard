/**
 * Core path-traversal guard.
 *
 * Design decisions, stated plainly:
 *
 * 1. POSIX only. Path separators are "/". On Windows you must normalize to POSIX
 *    before calling (the guard does not accept "\\"). Handling both would mean
 *    silently rewriting separators inside what is supposed to be a security
 *    primitive, and that is exactly where injection bugs live. One rule, applied
 *    uniformly, is safer than two rules that disagree on a corner case.
 *
 * 2. The guard resolves real symlink targets via fs.realpathSync against the
 *    root. This is the only way to catch a symlink that points outside root.
 *    A pure-lexical check cannot see through symlinks by definition. The cost is
 *    that root and any existing path being validated must exist on disk. For the
 *    intended use case — guarding paths about to be opened — this is acceptable;
 *    paths that do not yet exist cannot be symlink-attacked anyway, and we treat
 *    them as safe only if every existing ancestor is safe.
 *
 * 3. "Within root" is defined prefix-lexically on fully resolved absolute paths:
 *    target === root, or target starts with root + "/". A root of "/a/b" must NOT
 *    match "/a/bx" — the trailing-slash check prevents that. This is the classic
 *    prefix-confusion bug; we avoid it by requiring the boundary.
 *
 * 4. Input must be absolute after resolution. We do not guess a cwd. Callers who
 *    want relative-path convenience must resolve their own cwd and pass absolute
 *    paths in; the guard will not paper over that for them, because cwd in a
 *    server process is a frequent source of subtle security bugs.
 */

import { realpathSync, lstatSync, statSync } from 'node:fs';
import { sep, isAbsolute, normalize, dirname, join } from 'node:path';

/**
 * Resolved root used for comparison. We realpath the root so that if root itself
 * is a symlink we compare against its real location — otherwise a root like
 * "/var/data" pointing at "/srv/data" would let a symlink to "/srv/data/../../etc"
 * look "inside" because the prefix matched the un-resolved root string.
 */
function resolveRoot(root) {
  if (typeof root !== 'string' || root.length === 0) {
    throw new TypeError('root must be a non-empty string');
  }
  // Guard against accidental Windows-style backslashes sneaking in. We refuse
  // rather than rewrite; see decision 1 above.
  if (root.includes('\\')) {
    throw new Error(`root must use POSIX separators only, got: ${root}`);
  }
  if (!isAbsolute(root)) {
    throw new Error(`root must be absolute, got: ${root}`);
  }
  const normRoot = normalize(root);
  // realpathSync throws ENOENT if root does not exist; that is a caller bug.
  const realRoot = realpathSync(normRoot);
  return realRoot;
}

/**
 * True iff `target` is `realRoot` itself or a descendant of it. The descendant
 * test is deliberately `target === realRoot + sep + ...` rather than a bare
 * startsWith, to prevent the "/a/b" vs "/a/bx" prefix collision.
 */
function isWithin(target, realRoot) {
  if (target === realRoot) return true;
  const prefix = realRoot.endsWith(sep) ? realRoot : realRoot + sep;
  return target.startsWith(prefix);
}

/**
 * Walk up from `start` to the nearest existing ancestor, realpathSync it, and
 * then re-attach the non-existing tail. This is how we validate paths whose
 * final segment does not exist yet (common when creating files): we resolve the
 * existing prefix and check *that* stays in root, then reconstruct the full
 * resolved path lexically for the final within-root check.
 */
function resolvePathHandlingMissingSegments(absPath) {
  // First, does it exist directly? realpathSync only works on existing paths.
  let existingStat;
  try {
    existingStat = lstatSync(absPath);
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
    existingStat = null;
  }
  if (existingStat !== null) {
    return realpathSync(absPath);
  }
  // Walk up to nearest existing ancestor.
  let missingSegments = [];
  let current = absPath;
  while (true) {
    const parent = dirname(current);
    if (current === parent) {
      // Reached filesystem root without finding an existing ancestor. Treat
      // the path as genuinely unresolvable — caller passed a path whose entire
      // lineage is missing. Realpath against "/" would succeed but is not
      // meaningful for within-root checking; we let the prefix check decide.
      return normalize(absPath);
    }
    let parentStat;
    try {
      parentStat = lstatSync(parent);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
      parentStat = null;
    }
    if (parentStat !== null) {
      const realParent = realpathSync(parent);
      const tail = missingSegments.length > 0 ? sep + missingSegments.join(sep) : '';
      return realParent + tail;
    }
    // parent didn't exist either; record the segment we climbed past and continue.
    const seg = current.slice(parent.length + sep.length);
    missingSegments.unshift(seg);
    current = parent;
  }
}

/**
 * PathGuard validates that a resolved file path stays within a designated root
 * directory, rejecting symlink escapes and dot-segment escapes.
 */
export class PathGuard {
  /**
   * @param {string} root Absolute POSIX path to the allowed root directory.
   *        Must exist on disk (we realpath it in the constructor so subsequent
   *        checks are consistent).
   */
  constructor(root) {
    this._realRoot = resolveRoot(root);
  }

  /** The resolved root this guard was constructed against. */
  get root() {
    return this._realRoot;
  }

  /**
   * Validate that `target` resolves to a path within this guard's root.
   *
   * @param {string} target Absolute POSIX path. May point at a non-existent
   *        file (the nearest existing ancestor is resolved and checked).
   * @returns {{ safe: boolean, resolved: string }}
   *          `safe` is true iff the fully-resolved path is within root.
   *          `resolved` is the fully-resolved path we actually checked.
   * @throws {TypeError|Error} on malformed input (non-string, relative,
   *         backslash separators).
   */
  validate(target) {
    if (typeof target !== 'string' || target.length === 0) {
      throw new TypeError('target must be a non-empty string');
    }
    if (!isAbsolute(target)) {
      throw new Error(`target must be absolute, got: ${target}`);
    }
    if (target.includes('\\')) {
      throw new Error(`target must use POSIX separators only, got: ${target}`);
    }
    const resolved = resolvePathHandlingMissingSegments(target);
    return { safe: isWithin(resolved, this._realRoot), resolved };
  }

  /**
   * Boolean convenience wrapper around validate(). Returns true iff the path is
   * within root. Throws on the same malformed-input conditions as validate().
   */
  isSafe(target) {
    return this.validate(target).safe;
  }
}
