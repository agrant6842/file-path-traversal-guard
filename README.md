# file-path-traversal-guard

A small, dependency-free TypeScript-style ESM library that validates a resolved file path stays inside a designated root directory, rejecting both dot-segment escapes (`../../etc/passwd`) and symlink escapes.

## Usage

```js
import { PathGuard } from 'file-path-traversal-guard';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Create a real root directory for the guard.
const sandbox = mkdtempSync(join(tmpdir(), 'uploads-'));
const root = join(sandbox, 'uploads');
mkdirSync(root, { recursive: true });
writeFileSync(join(root, 'photo.png'), Buffer.alloc(0));

const guard = new PathGuard(root);

const { safe, resolved } = guard.validate(join(root, 'photo.png'));
// safe === true, resolved === the real path of root/photo.png

// Dot-segment escape past root.
const escaped = guard.validate(join(root, '..', '..', 'etc', 'passwd'));
// escaped.safe === false

// Symlink inside root pointing outside root.
symlinkSync('/etc', join(root, 'symlink-to-elsewhere'));
const throughLink = guard.validate(join(root, 'symlink-to-elsewhere', 'passwd'));
// throughLink.safe === false  (the symlink's real target was outside root)
```

`PathGuard` exposes `validate(target)` returning `{ safe: boolean, resolved: string }`, and an `isSafe(target)` boolean convenience wrapper.

## Why this exists

When a server lets a user influence a file path — an upload destination, a template include, a static-file lookup — the two classic escape routes are dot-segments that walk above the intended root, and symlinks created inside the root that point outside it. A purely lexical check (string-prefix on a normalized path) catches the first but is blind to the second, because it never asks the filesystem where a symlink actually goes. This library resolves symlinks with `fs.realpathSync` against the root and then does a strict prefix check on the resolved path.

The trade-off: the root directory must exist when the guard is constructed, and any existing ancestor of a target must exist on disk so it can be resolved. For the intended use case — guarding paths that are about to be opened — that is fine; a path that doesn't exist yet cannot be symlink-attacked through its own non-existent tail, and we resolve the nearest existing ancestor to make sure *that* is inside root before reconstructing the full path lexically.

## The awkward edge

POSIX only. The guard refuses backslash separators rather than silently rewriting them. If you are on Windows, normalize your paths to forward slashes before constructing a `PathGuard` — mixing separator styles inside a security primitive is exactly the kind of ambiguity that produces injection bugs, so this library picks one rule and enforces it.

The root must be absolute and must exist. Inputs must be absolute. The guard does not guess a working directory for you, because relying on `process.cwd()` inside a security check is a frequent source of subtle bugs.

## Performance

The window keeps a bounded buffer, so `push` is constant time and memory does not
grow with the length of the stream. `peak` and `trough` are linear in the window
size, which is the trade that keeps `push` cheap.

## Limitations

Values are coerced to floats, so very large integers lose precision. If you need
exact integer aggregates over a window, this is the wrong tool.

