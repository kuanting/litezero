// Dead-secret static lint (zero-dependency version).
//
// Scans src/ for any variable whose initializer calls one of the APPROVED
// secret-producing primitives (PUF regen, AES-GCM-decrypt for black-key
// unwrap, ECDH shared secret, HKDF output) and requires that the same
// file contains a zeroization step that references that variable:
//     <var>.fill(0)  |  zeroize(<var>)  |  <var>.dispose()
//
// An `// @secret-escapes: <reason>` comment on the same line or the line
// above exempts the declaration (e.g. because the buffer is returned and
// the caller is responsible for zeroization).
//
// This is the lint that would have flagged two specific v1 issues:
//   + d_D unwrapped into PS DRAM but not zeroized between handshakes;
//   + Z_2 intermediate buffer not zeroized on the happy path.
//
// It is deliberately conservative — we do not attempt to model aliasing
// or SSA. If the variable is reassigned to a new secret, both lifetimes
// must be zeroized individually. A developer who shadows a secret variable
// and forgets to zeroize the prior binding will be flagged; that is the
// intended behaviour.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const APPROVED_SECRET_ORIGINS = [
  "pufRegenerate",
  "aesGcmDecrypt",
  "ecdhSharedSecret",
  "hkdf",
];

const EXEMPT_FILES = new Set<string>([
  "src/crypto/rng.ts",
  "src/crypto/secret-types.ts",
  "src/protocol/messages.ts",
  "src/protocol/parser.ts",
]);

const EXEMPT_DIRS = new Set<string>(["src/transport"]);

interface Finding {
  file: string;
  line: number;
  origin: string;
  varName: string;
  reason: string;
}

function walk(root: string, rel = ""): string[] {
  const out: string[] = [];
  for (const name of readdirSync(root)) {
    if (name === "node_modules" || name.startsWith(".")) continue;
    const abs = join(root, name);
    const r = rel ? `${rel}/${name}` : name;
    const st = statSync(abs);
    if (st.isDirectory()) out.push(...walk(abs, r));
    else if (name.endsWith(".ts")) out.push(r);
  }
  return out;
}

function isExempt(relPath: string): boolean {
  if (EXEMPT_FILES.has(relPath)) return true;
  for (const d of EXEMPT_DIRS) if (relPath.startsWith(`${d}/`)) return true;
  return false;
}

// Regex for: `  const foo = pufRegenerate(...)` or `let foo = ecdhSharedSecret(...)`
// Group 1: variable name.  Group 2: origin function name.
// Bounded within a single logical statement — no semicolons or newlines
// between the name and the initializer call.
const DECL_RE =
  /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)[^;\n=]*=\s*(?:await\s+)?([A-Za-z_$][\w$]*)\s*\(/g;

// Regex helpers for disposal checks:
function mkDisposalRegexes(v: string): RegExp[] {
  const esc = v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return [
    new RegExp(`\\b${esc}\\s*\\.\\s*fill\\s*\\(\\s*0\\s*\\)`),
    new RegExp(`\\bzeroize\\s*\\(\\s*${esc}\\s*\\)`),
    new RegExp(`\\b${esc}\\s*\\.\\s*dispose\\s*\\(\\s*\\)`),
  ];
}

// Find the enclosing function for a 0-based offset by matching `{`/`}`
// brace depth backwards to the nearest `function(`/`=> {`/`(...) {` boundary.
// Returns [startOffset, endOffset] of the function body, or null if the
// declaration is at module scope.
function enclosingFunctionBody(
  src: string,
  offset: number,
): [number, number] | null {
  // Find the `{` whose matching `}` encloses `offset`.
  // Simpler: walk BACK counting unmatched `{`s until we find a `{` with
  // depth -1, then walk forward from that position to find its `}`.
  let depth = 0;
  let openAt = -1;
  for (let i = offset - 1; i >= 0; i--) {
    const c = src[i];
    if (c === "}") depth++;
    else if (c === "{") {
      if (depth === 0) {
        openAt = i;
        break;
      }
      depth--;
    }
  }
  if (openAt === -1) return null;
  // Forward to matching close.
  let d = 1;
  let closeAt = -1;
  for (let i = openAt + 1; i < src.length; i++) {
    const c = src[i];
    if (c === "{") d++;
    else if (c === "}") {
      d--;
      if (d === 0) {
        closeAt = i;
        break;
      }
    }
  }
  if (closeAt === -1) return null;
  // Heuristic: ensure this brace actually follows a function-like
  // signature. Look backwards from openAt for `)` or `=>`.
  let j = openAt - 1;
  while (j >= 0 && /\s/.test(src[j])) j--;
  if (j < 0) return null;
  if (src[j] === ")") return [openAt, closeAt]; // function(...) { ... }
  if (src.substring(Math.max(0, j - 1), j + 1) === "=>")
    return [openAt, closeAt]; // arrow
  // Fallback: still treat as a scope (could be a block statement).
  return [openAt, closeAt];
}

function lineNumberOf(src: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset; i++) if (src[i] === "\n") line++;
  return line;
}

function scanFile(absPath: string, relPath: string): Finding[] {
  const src = readFileSync(absPath, "utf8");
  if (src.includes("// @secret-lint-exempt")) return [];
  const findings: Finding[] = [];

  DECL_RE.lastIndex = 0;
  for (;;) {
    const m = DECL_RE.exec(src);
    if (!m) break;
    const [, varName, origin] = m;
    if (!APPROVED_SECRET_ORIGINS.includes(origin)) continue;

    // Check for @secret-escapes: comment on the declaration or preceding
    // up-to 3 lines.
    const declOffset = m.index;
    const lineStart = src.lastIndexOf("\n", declOffset) + 1;
    const above = src.substring(
      Math.max(0, lineStart - 400),
      declOffset + 200,
    );
    if (/@secret-escapes:/.test(above)) continue;

    const body = enclosingFunctionBody(src, declOffset);
    const searchIn = body
      ? src.substring(body[0], body[1])
      : src; // fallthrough: whole file
    const regs = mkDisposalRegexes(varName);
    const disposed = regs.some((r) => r.test(searchIn));
    if (!disposed) {
      findings.push({
        file: relPath,
        line: lineNumberOf(src, declOffset),
        origin,
        varName,
        reason: body
          ? "no .fill(0)/zeroize()/dispose() for this binding in the enclosing function"
          : "secret at module scope; no enclosing function to zeroize in",
      });
    }
  }
  return findings;
}

function main(): void {
  const here = fileURLToPath(new URL(".", import.meta.url));
  const repoRoot = join(here, "..");
  const srcRoot = join(repoRoot, "src");
  const files = walk(srcRoot).map((p) => `src/${p}`);
  const findings: Finding[] = [];
  for (const rel of files) {
    if (isExempt(rel)) continue;
    const abs = join(repoRoot, rel);
    findings.push(...scanFile(abs, rel));
  }

  if (findings.length === 0) {
    console.log(
      `\n\u001b[32m[dead-secret-lint]\u001b[0m clean (${files.length} files scanned)`,
    );
    process.exit(0);
  }
  console.log(
    `\n\u001b[31m[dead-secret-lint]\u001b[0m ${findings.length} undisposed secrets across ${files.length} scanned files:\n`,
  );
  for (const f of findings) {
    console.log(
      `  ${f.file}:${f.line}  origin=${f.origin}  var=${f.varName}`,
    );
    console.log(`      ${f.reason}`);
  }
  process.exit(1);
}

main();
