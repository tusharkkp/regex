/**
 * ============================================================
 *  validation.js
 *  Secure File Upload System — Regex-Based Web Form Validation
 * ============================================================
 *  Course  : Theory of Computation (2304220T)
 *  Topic   : 25 — Secure File Upload System
 *  Student : Tushar Kaldate | PRN: 202401040191 | Roll: 285
 *  AY      : 2025–26
 * ============================================================
 *
 *  THEORETICAL FOUNDATION
 *  ──────────────────────
 *  Every validation pattern in this file is a regular expression
 *  over a finite alphabet Σ. By Kleene's Theorem (1956), each
 *  regex corresponds to a Deterministic Finite Automaton (DFA)
 *  that recognises exactly the same language — confirming that
 *  all validated languages belong to the class REG (regular
 *  languages) in the Chomsky hierarchy.
 *
 *  Closure properties exploited:
 *    • Concatenation  — email = local · {@} · domain · {.} · tld
 *    • Union          — (jpg|png|pdf|docx|txt)
 *    • Kleene Star    — [a-zA-Z0-9_]* for repeated characters
 *    • Complement     — negative lookaheads (?!...) ≡ ¬L
 *    • Intersection   — L_whitelist ∩ ¬L_blocklist (File Extension)
 *    • Length bounds  — {n,m} ≡ DFA counting states
 *
 *  CO Mapping:
 *    CO.1  — DFA/NFA identified per field; choice justified
 *    CO.2  — Regex ≡ regular grammar; DFA constructed for 2 fields
 *    CO.3  — Formal L definitions; correctness verified via tests
 *    CO.4  — All 6 languages confirmed regular (DFA sufficient)
 *    CO.5  — Regex validation (decidable) vs NLP parsing compared
 * ============================================================
 */

'use strict';

/* ============================================================
   SECTION 1 — REGEX PATTERN CONSTANTS
   All patterns defined here with:
     - Formal language definition  L = { w ∈ Σ* | ... }
     - Alphabet (Σ)
     - Component-level annotation
     - Automata class
   Using Object.freeze() so patterns cannot be accidentally
   modified at runtime — supports defensive programming.
   ============================================================ */

const PATTERNS = Object.freeze({

  /**
   * FIELD 1 — USERNAME
   * ──────────────────
   * Alphabet : Σ = { a–z, A–Z, 0–9, _ }
   * Language : L₁ = { w ∈ Σ* | 3 ≤ |w| ≤ 20,
   *                             w ∈ [a-zA-Z0-9_]*,
   *                             w ∉ [0-9]+ }
   * Automata : Regular — DFA with O(21) length-counting states
   *
   * Regex breakdown:
   *   ^              → anchor: match from string start (no partial match)
   *   (?![0-9]+$)    → NEGATIVE LOOKAHEAD: reject all-digit strings
   *                    Formal: L₁ ∩ ¬([0-9]+)  — intersection + complement
   *   [a-zA-Z0-9_]   → character class: letters, digits, underscore ONLY
   *                    Blocks spaces, hyphens, special chars
   *   {3,20}         → quantifier: minimum 3, maximum 20 characters
   *                    Implemented as DFA counting states q₀…q₂₀
   *   $              → anchor: match at string end (prevents suffix bypass)
   */
  USERNAME: /^(?![0-9]+$)[a-zA-Z0-9_]{3,20}$/,

  /**
   * FIELD 2 — EMAIL ADDRESS
   * ───────────────────────
   * Alphabet : Σ = { a–z, A–Z, 0–9, ., _, %, +, -, @ }
   * Language : L₂ = { u@d.t | u ∈ [a-zA-Z0-9._%+\-]+,
   *                            d ∈ [a-zA-Z0-9.\-]+,
   *                            t ∈ [a-zA-Z]{2,} }
   * Automata : Regular — 6-state DFA (see Theory Supplement §3)
   *            Equivalent to concatenation of 5 regular languages
   *
   * Regex breakdown:
   *   ^                      → start anchor
   *   [a-zA-Z0-9._%+\-]+     → LOCAL PART: one or more allowed chars
   *                             '+' means at least one (DFA: q₀→q₁ on first char)
   *   @                      → LITERAL '@': mandatory separator
   *                             (DFA transition q₁→q₂)
   *   [a-zA-Z0-9.\-]+        → DOMAIN: letters, digits, dots, hyphens
   *                             (DFA self-loop at q₃)
   *   \.                     → ESCAPED DOT: literal '.' (not wildcard)
   *                             (DFA transition q₃→q₄)
   *   [a-zA-Z]{2,}           → TLD: minimum 2 alphabetic chars (com, edu, in)
   *                             No digits in TLD — security requirement
   *   $                      → end anchor
   */
  EMAIL: /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/,

  /**
   * FIELD 3a — FILE NAME (primary)
   * ─────────────────────────────
   * Alphabet : Σ = { a–z, A–Z, 0–9, _, -, . }
   * Language : L₃ = { w.e | w ∈ [a-zA-Z0-9_\-]{1,50},
   *                          e ∈ {jpg, jpeg, png, pdf, docx, txt},
   *                          w does not contain '.' }
   * Automata : Regular — concatenation of regular base-name + finite ext set
   *
   * Regex breakdown:
   *   ^                              → start anchor
   *   (?!.*\.\w+\.\w+)               → NEGATIVE LOOKAHEAD (security):
   *                                    blocks double-extension attacks
   *                                    e.g. "malware.pdf.exe" rejected
   *                                    Formal: L₃ ∩ ¬(Σ*\.w+\.w+)
   *   [a-zA-Z0-9_\-]{1,50}           → SAFE BASE NAME: no spaces, slashes,
   *                                    or special chars (path traversal blocked)
   *   \.                             → escaped literal dot
   *   (jpg|jpeg|png|pdf|docx|txt)    → WHITELIST UNION: only 6 safe extensions
   *                                    Finite set → trivially regular
   *   $                              → end anchor
   */
  FILE_NAME: /^(?!.*\.\w+\.\w+)[a-zA-Z0-9_\-]{1,50}\.(jpg|jpeg|png|pdf|docx|txt)$/i,

  /**
   * FIELD 3b — FILE NAME (no leading/trailing hyphens — additional strictness)
   * Catches edge cases like "-filename.pdf" or "filename-.pdf"
   * Alphabet : same as L₃
   * Additional constraint: base name must start and end with alphanumeric/underscore
   */
  FILE_NAME_STRICT: /^(?!.*\.\w+\.\w+)[a-zA-Z0-9_][a-zA-Z0-9_\-]{0,48}[a-zA-Z0-9_]\.(jpg|jpeg|png|pdf|docx|txt)$|^[a-zA-Z0-9_]\.(jpg|jpeg|png|pdf|docx|txt)$/i,

  /**
   * FIELD 4a — FILE EXTENSION (whitelist — primary)
   * ────────────────────────────────────────────────
   * Alphabet : Σ = { ., a–z, A–Z, 0–9 }
   * Language : L₄ = { .e | e ∈ {jpg, jpeg, png, pdf, docx, txt} }
   *            L₄ ⊂ Σ* — finite set of strings (trivially regular)
   * Automata : Regular — finite-state DFA with 1 path per extension
   *
   * Regex breakdown:
   *   ^                              → start anchor
   *   \.                             → mandatory leading dot
   *   (jpg|jpeg|png|pdf|docx|txt)    → union of 6 safe extensions
   *   $                              → end anchor (no suffix allowed)
   */
  FILE_EXT_WHITELIST: /^\.(jpg|jpeg|png|pdf|docx|txt)$/i,

  /**
   * FIELD 4b — FILE EXTENSION (blocklist — security layer)
   * Formal: L_bad = { .exe, .bat, .sh, .cmd, .vbs, .ps1, .msi,
   *                   .dll, .php, .js, .py, .rb, .pl, .jar, .swf }
   * Accepted language = L₄_whitelist ∩ ¬L_bad
   * Both L_whitelist and L_bad are regular (finite sets).
   * Regular languages are closed under complement and intersection
   * → accepted language is regular.
   *
   * Regex breakdown:
   *   (?!\.(exe|bat|sh|...)) → NEGATIVE LOOKAHEAD blocklist at position 0
   *   \.[a-zA-Z0-9]{2,10}    → generic extension structure (2–10 chars)
   */
  FILE_EXT_BLOCKLIST: /^\.(exe|bat|sh|cmd|vbs|ps1|msi|dll|php|js|py|rb|pl|jar|swf|pif|scr|hta|reg|cpl|inf|lnk)$/i,

  /**
   * FIELD 5 — FILE SIZE (MB)
   * ────────────────────────
   * Alphabet : Σ = { 0–9, . }
   * Language : L₅ = { w ∈ Σ* | w = d⁺(\.d{1,2})?,
   *                             0 < parseFloat(w) ≤ 100 }
   *            where d⁺ = one or more digits
   * Automata : Regular (structural pattern); range check is
   *            a decidable O(1) semantic post-filter
   *
   * Regex breakdown:
   *   ^          → start anchor
   *   \d+        → INTEGER PART: one or more digits  (Kleene+ on \d)
   *   (          → start optional group
   *     \.       → escaped dot (decimal separator)
   *     \d{1,2}  → DECIMAL PART: exactly 1 or 2 digits
   *               {1,2} is more efficient than {1,2}? — avoids backtracking
   *   )?         → end optional group (decimal part is optional)
   *   $          → end anchor
   *
   * Range constraint:  0 < value ≤ 100  (applied after regex in JS)
   * Min accepted:  0.01 MB  |  Max accepted: 100 MB  |  Max decimals: 2
   */
  FILE_SIZE: /^\d+(\.\d{1,2})?$/,

  /**
   * FIELD 6 — DESCRIPTION
   * ─────────────────────
   * Alphabet : Σ = { a–z, A–Z, 0–9, space, ., ,, !, ?, ', - }
   * Language : L₆ = { w ∈ Σ* | 10 ≤ |w| ≤ 300,
   *                             w ∉ (whitespace-only strings) }
   * Automata : Regular — DFA with 301 length-counting states
   *
   * Regex breakdown:
   *   ^                    → start anchor
   *   (?!\s*$)             → NEGATIVE LOOKAHEAD: rejects strings
   *                          consisting entirely of whitespace
   *                          Formal: L₆ ∩ ¬(\s*) — complement + intersection
   *                          This also blocks empty-after-trim attacks
   *   [a-zA-Z0-9\s.,!?'\-] → SAFE CHARACTER CLASS:
   *                          • Alphanumeric allowed
   *                          • \s: space and tab allowed (human text)
   *                          • .,!?'- : basic punctuation only
   *                          • BLOCKED: < > & " / \ = { } (XSS/injection)
   *   {10,300}             → LENGTH BOUNDS: min 10, max 300 chars
   *   $                    → end anchor
   */
  DESCRIPTION: /^(?!\s*$)[a-zA-Z0-9\s.,!?'\-]{10,300}$/,

  /**
   * SECURITY AUXILIARY PATTERNS
   * ───────────────────────────
   * These patterns detect known attack signatures.
   * They are used in the security pre-screening layer
   * BEFORE field-specific validation runs.
   */

  /**
   * XSS_DETECT — Detects common Cross-Site Scripting payloads
   * Looks for HTML tags, script injections, event handlers
   * Formal: L_xss ⊂ Σ* — any string containing < > or javascript:
   */
  XSS_DETECT: /<[^>]*>|javascript\s*:|on\w+\s*=|<script|<\/script|alert\s*\(|eval\s*\(/i,

  /**
   * SQL_DETECT — Detects common SQL injection patterns
   * Formal: L_sql ⊂ Σ* — strings with SQL keywords in injection context
   */
  SQL_DETECT: /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC|CAST)\b)|(';\s*--|;\s*DROP|1\s*=\s*1)/i,

  /**
   * PATH_TRAVERSAL — Detects directory traversal sequences
   * Formal: L_path ⊂ Σ* — strings containing ../ or ..\
   */
  PATH_TRAVERSAL: /\.\.[/\\]|[/\\]\.\.|^[/\\]/,

  /**
   * NULL_BYTE — Detects null byte injection (%00 or \0)
   * Used to bypass extension checks in vulnerable systems
   */
  NULL_BYTE: /\0|%00/,

  /**
   * UNICODE_EXPLOIT — Detects suspicious unicode override characters
   */
  UNICODE_EXPLOIT: /[\u202A-\u202E\u2066-\u2069\uFEFF]/,
});

/* ============================================================
   SECTION 2 — VALIDATION CONSTANTS
   All magic numbers and limit values in one place.
   Centralizing constants reduces redundancy (Efficiency criterion).
   ============================================================ */

const LIMITS = Object.freeze({
  USERNAME_MIN:      3,
  USERNAME_MAX:      20,
  FILE_NAME_MAX:     50,
  FILE_SIZE_MIN:     0.01,   // MB
  FILE_SIZE_MAX:     100.00, // MB
  FILE_SIZE_DECIMAL: 2,      // max decimal places
  DESC_MIN:          10,
  DESC_MAX:          300,
  UPLOAD_MAX_BYTES:  104857600, // 100 MB in bytes

  ALLOWED_EXTENSIONS: Object.freeze(['jpg', 'jpeg', 'png', 'pdf', 'docx', 'txt']),
  BLOCKED_EXTENSIONS: Object.freeze([
    'exe','bat','sh','cmd','vbs','ps1','msi','dll','php',
    'js','py','rb','pl','jar','swf','pif','scr','hta',
    'reg','cpl','inf','lnk'
  ]),
  ALLOWED_MIME_TYPES: Object.freeze([
    'image/jpeg','image/png','application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'text/plain'
  ]),
});

/* ============================================================
   SECTION 3 — UTILITY & UI HELPERS
   Pure helper functions with no side effects where possible.
   Each function has a single, well-defined responsibility
   (Single Responsibility Principle).
   ============================================================ */

/**
 * Sets the visual validation state of a form field and its
 * feedback element. Updates ARIA attributes for accessibility.
 *
 * @param {string}  fieldId  - The id of the <input>/<textarea>
 * @param {boolean} isValid  - true = valid, false = invalid
 * @param {string}  message  - Human-readable feedback message
 * @param {string}  [type]   - 'error' | 'warning' | 'success'
 *                             Defaults based on isValid
 */
function setFeedback(fieldId, isValid, message, type) {
  const input    = document.getElementById(fieldId);
  const feedback = document.getElementById(`fb-${fieldId}`);

  if (!input || !feedback) return; // Guard: DOM elements must exist

  // ── Visual state classes ─────────────────────────────────
  input.classList.remove('valid', 'invalid', 'warning');
  feedback.classList.remove('ok', 'err', 'warn');

  const resolvedType = type || (isValid ? 'success' : 'error');
  if (resolvedType === 'success') {
    input.classList.add('valid');
    feedback.classList.add('ok');
  } else if (resolvedType === 'warning') {
    input.classList.add('warning');
    feedback.classList.add('warn');
  } else {
    input.classList.add('invalid');
    feedback.classList.add('err');
  }

  // ── Feedback text ────────────────────────────────────────
  feedback.textContent = message;

  // ── ARIA attributes (accessibility — CO.5 / UX criterion) ─
  input.setAttribute('aria-invalid', isValid ? 'false' : 'true');
  input.setAttribute('aria-describedby', `fb-${fieldId}`);
  feedback.setAttribute('role', 'alert');
  feedback.setAttribute('aria-live', 'polite');
}

/**
 * Clears the validation state of a single field back to neutral.
 * Called on field focus (before user has entered anything).
 *
 * @param {string} fieldId - The id of the form field
 */
function clearFeedback(fieldId) {
  const input    = document.getElementById(fieldId);
  const feedback = document.getElementById(`fb-${fieldId}`);
  if (!input || !feedback) return;
  input.classList.remove('valid', 'invalid', 'warning');
  feedback.classList.remove('ok', 'err', 'warn');
  feedback.textContent = '';
  input.removeAttribute('aria-invalid');
}

/**
 * Counts validated fields and updates the summary counter.
 * Provides real-time "X / 6 fields valid" progress indicator.
 */
function updateSummary() {
  const REQUIRED_FIELDS = ['username', 'email', 'filename', 'filetype', 'filesize', 'description'];
  const validCount = REQUIRED_FIELDS.filter(id => {
    const el = document.getElementById(id);
    return el && el.classList.contains('valid');
  }).length;

  const counterEl = document.getElementById('validCount');
  if (counterEl) counterEl.textContent = validCount;

  // Change summary colour when all fields pass
  const summaryEl = document.getElementById('valSummary');
  if (summaryEl) {
    summaryEl.classList.toggle('all-valid', validCount === REQUIRED_FIELDS.length);
  }
}

/**
 * Displays a toast notification in the bottom-right corner.
 * Auto-dismisses after 4 seconds.
 *
 * @param {string}  message - Text to display
 * @param {boolean} success - true = green success, false = red error
 */
function showToast(message, success) {
  const toast = document.getElementById('toast');
  if (!toast) return;

  toast.textContent = message;
  toast.className = `show ${success ? 'success' : 'error'}`;

  // Clear any existing dismiss timer
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => {
    toast.className = toast.className.replace('show', '').trim();
  }, 4000);
}

/**
 * Sanitizes a string for safe display in the DOM.
 * Converts HTML special characters to entities, preventing
 * any reflected XSS even in error messages.
 *
 * @param   {string} str - Raw input string
 * @returns {string} HTML-entity-escaped string
 */
function sanitizeForDisplay(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Counts the number of decimal places in a numeric string.
 * Used by validateFileSize to enforce the {1,2} decimal limit.
 *
 * @param   {string} str - e.g. "4.75" → returns 2
 * @returns {number} Number of decimal digits (0 if integer)
 */
function decimalPlaces(str) {
  const dotIndex = str.indexOf('.');
  return dotIndex === -1 ? 0 : str.length - dotIndex - 1;
}

/**
 * Extracts the file extension (with leading dot, lowercased)
 * from a filename string.
 *
 * @param   {string} filename - e.g. "report.PDF" → returns ".pdf"
 * @returns {string|null}     - e.g. ".pdf" or null if no extension
 */
function getExtension(filename) {
  const lastDot = filename.lastIndexOf('.');
  if (lastDot === -1 || lastDot === 0) return null;
  return filename.slice(lastDot).toLowerCase();
}

/* ============================================================
   SECTION 4 — SECURITY PRE-SCREEN
   Runs before field-specific validation.
   Checks all input against known attack patterns.
   Returns an object { safe: bool, threat: string|null }.
   ============================================================ */

/**
 * Security pre-screen: checks a value against all known
 * attack-pattern regexes before field-level validation.
 *
 * Languages blocked (all complements of regular languages):
 *   ¬L_xss    = strings NOT containing HTML/script payloads
 *   ¬L_sql    = strings NOT containing SQL injection keywords
 *   ¬L_path   = strings NOT containing path traversal sequences
 *   ¬L_null   = strings NOT containing null bytes
 *   ¬L_uni    = strings NOT containing unicode direction overrides
 *
 * @param   {string} value - Raw field value
 * @returns {{ safe: boolean, threat: string|null }}
 */
function securityPreScreen(value) {
  if (PATTERNS.XSS_DETECT.test(value)) {
    return { safe: false, threat: 'XSS payload detected — HTML tags and scripts are not permitted' };
  }
  if (PATTERNS.SQL_DETECT.test(value)) {
    return { safe: false, threat: 'SQL injection pattern detected — SQL keywords are not permitted' };
  }
  if (PATTERNS.PATH_TRAVERSAL.test(value)) {
    return { safe: false, threat: 'Path traversal detected — "../" sequences are not permitted' };
  }
  if (PATTERNS.NULL_BYTE.test(value)) {
    return { safe: false, threat: 'Null byte injection detected — this input is not permitted' };
  }
  if (PATTERNS.UNICODE_EXPLOIT.test(value)) {
    return { safe: false, threat: 'Suspicious unicode character detected — not permitted' };
  }
  return { safe: true, threat: null };
}

/* ============================================================
   SECTION 5 — FIELD VALIDATORS
   One pure validation function per field.
   Naming convention: validate<FieldName>(inputElement)
   Each function:
     1. Reads and trims the input value
     2. Runs security pre-screen
     3. Validates with the primary regex
     4. Applies additional checks (secondary regex, range, etc.)
     5. Builds a specific, actionable error message
     6. Calls setFeedback() and updateSummary()
     7. Returns { valid: boolean, value: string, errors: string[] }
   ============================================================ */

/**
 * Validates the Username field.
 *
 * Formal language:
 *   Σ  = { a–z, A–Z, 0–9, _ }
 *   L₁ = { w ∈ Σ* | 3 ≤ |w| ≤ 20, w ∈ [a-zA-Z0-9_]*, w ∉ [0-9]+ }
 *
 * Rules enforced:
 *   ✓ 3–20 characters
 *   ✓ Letters, digits, underscore only
 *   ✓ Not exclusively digits (negative lookahead)
 *   ✓ No spaces, hyphens, or special characters
 *   ✓ Security pre-screen passes
 *
 * @param   {HTMLInputElement} input - The username input element
 * @returns {{ valid: boolean, value: string, errors: string[] }}
 */
function validateUsername(input) {
  const raw    = input.value;
  const value  = raw.trim();
  const errors = [];

  // ── Security pre-screen ────────────────────────────────────
  const security = securityPreScreen(value);
  if (!security.safe) {
    setFeedback('username', false, `⚠ Security: ${security.threat}`);
    updateSummary();
    return { valid: false, value, errors: [security.threat] };
  }

  // ── Empty check (before regex — gives specific message) ────
  if (value.length === 0) {
    setFeedback('username', false, '✗ Username is required');
    updateSummary();
    return { valid: false, value, errors: ['Username is required'] };
  }

  // ── Length check (before full regex — faster fail) ─────────
  if (value.length < LIMITS.USERNAME_MIN) {
    const msg = `✗ Too short — ${value.length} of ${LIMITS.USERNAME_MIN} minimum characters`;
    setFeedback('username', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }
  if (value.length > LIMITS.USERNAME_MAX) {
    const msg = `✗ Too long — ${value.length} chars (max ${LIMITS.USERNAME_MAX})`;
    setFeedback('username', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── All-digits check (extracted from lookahead for clarity) ─
  // Formally: w ∉ [0-9]+ — intersection with complement of digit-only strings
  if (/^[0-9]+$/.test(value)) {
    const msg = '✗ Username cannot be entirely numeric — include at least one letter or underscore';
    setFeedback('username', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Character class check ───────────────────────────────────
  const invalidChars = value.match(/[^a-zA-Z0-9_]/g);
  if (invalidChars) {
    const unique = [...new Set(invalidChars)].map(c => `"${c}"`).join(', ');
    const msg = `✗ Invalid character(s) ${unique} — only letters, digits, underscore allowed`;
    setFeedback('username', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Primary regex (full formal validation) ──────────────────
  // L₁ = { w ∈ Σ* | 3 ≤ |w| ≤ 20, w ∈ [a-zA-Z0-9_]*, w ∉ [0-9]+ }
  if (!PATTERNS.USERNAME.test(value)) {
    const msg = '✗ Username format invalid — use 3–20 letters, digits, or underscores';
    setFeedback('username', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── All checks passed ────────────────────────────────────────
  setFeedback('username', true, `✓ Valid username (${value.length} chars)`);
  updateSummary();
  return { valid: true, value, errors: [] };
}

/**
 * Validates the Email Address field.
 *
 * Formal language:
 *   Σ  = { a–z, A–Z, 0–9, ., _, %, +, -, @ }
 *   L₂ = { u@d.t | u ∈ [a-zA-Z0-9._%+\-]+,
 *                   d ∈ [a-zA-Z0-9.\-]+,
 *                   t ∈ [a-zA-Z]{2,} }
 *   By concatenation closure: L₂ is regular (DFA: 6 states)
 *
 * Rules enforced:
 *   ✓ Exactly one '@' symbol
 *   ✓ Non-empty local part before '@'
 *   ✓ Valid domain label after '@'
 *   ✓ At least one dot in domain
 *   ✓ TLD at least 2 alphabetic characters
 *   ✓ No consecutive dots
 *   ✓ Security pre-screen passes
 *
 * @param   {HTMLInputElement} input - The email input element
 * @returns {{ valid: boolean, value: string, errors: string[] }}
 */
function validateEmail(input) {
  const raw   = input.value;
  const value = raw.trim().toLowerCase(); // Normalize to lowercase
  const errors = [];

  // ── Security pre-screen ────────────────────────────────────
  const security = securityPreScreen(value);
  if (!security.safe) {
    setFeedback('email', false, `⚠ Security: ${security.threat}`);
    updateSummary();
    return { valid: false, value, errors: [security.threat] };
  }

  if (value.length === 0) {
    setFeedback('email', false, '✗ Email address is required');
    updateSummary();
    return { valid: false, value, errors: ['Email is required'] };
  }

  // ── Structural checks (ordered from cheapest to most expensive) ─

  // Must contain exactly one '@'
  const atCount = (value.match(/@/g) || []).length;
  if (atCount === 0) {
    const msg = '✗ Missing "@" — format must be: user@domain.tld';
    setFeedback('email', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }
  if (atCount > 1) {
    const msg = '✗ Multiple "@" symbols — only one is permitted';
    setFeedback('email', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  const [localPart, domainPart] = value.split('@');

  // Local part must be non-empty
  if (!localPart || localPart.length === 0) {
    const msg = '✗ Local part is empty — something must appear before "@"';
    setFeedback('email', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // Domain must contain at least one dot
  if (!domainPart || !domainPart.includes('.')) {
    const msg = '✗ Domain must contain a dot — e.g. "domain.com"';
    setFeedback('email', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // No consecutive dots allowed (common mistake)
  if (/\.\./.test(value)) {
    const msg = '✗ Consecutive dots ".." are not permitted in an email address';
    setFeedback('email', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // Domain cannot start or end with a dot or hyphen
  if (/^\.|-$|^\-/.test(domainPart)) {
    const msg = '✗ Domain cannot start or end with "." or "-"';
    setFeedback('email', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Primary regex (full formal validation) ──────────────────
  // L₂ = { u@d.t | u ∈ [a-zA-Z0-9._%+\-]+, d ∈ [a-zA-Z0-9.\-]+, t ∈ [a-zA-Z]{2,} }
  if (!PATTERNS.EMAIL.test(value)) {
    const msg = '✗ Invalid email — format: user@domain.tld (e.g. tushar@college.edu)';
    setFeedback('email', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // Extract and validate TLD length explicitly
  const tld = domainPart.split('.').pop();
  if (tld.length < 2) {
    const msg = `✗ TLD ".${tld}" too short — must be at least 2 letters (e.g. .com, .edu, .in)`;
    setFeedback('email', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  setFeedback('email', true, `✓ Valid email address`);
  updateSummary();
  return { valid: true, value, errors: [] };
}

/**
 * Validates the File Name field.
 *
 * Formal language:
 *   Σ  = { a–z, A–Z, 0–9, _, -, . }
 *   L₃ = { w.e | w ∈ [a-zA-Z0-9_\-]{1,50},
 *                  e ∈ {jpg, jpeg, png, pdf, docx, txt},
 *                  no double extension in w.e }
 *   Closure: concatenation of L_base (regular) and L_ext (finite → regular)
 *
 * Security rules enforced:
 *   ✓ No double-extension attacks (e.g. malware.pdf.exe) — negative lookahead
 *   ✓ No spaces (prevents command injection)
 *   ✓ No path separators / \ (prevents path traversal)
 *   ✓ No null bytes (prevents null-byte extension bypass)
 *   ✓ Base name ≤ 50 characters
 *   ✓ Extension in whitelist {jpg, jpeg, png, pdf, docx, txt}
 *   ✓ Must not be hidden file (starting with dot)
 *
 * @param   {HTMLInputElement} input - The filename input element
 * @returns {{ valid: boolean, value: string, errors: string[] }}
 */
function validateFileName(input) {
  const raw   = input.value;
  const value = raw.trim();

  // ── Security pre-screen ────────────────────────────────────
  const security = securityPreScreen(value);
  if (!security.safe) {
    setFeedback('filename', false, `⚠ Security: ${security.threat}`);
    updateSummary();
    return { valid: false, value, errors: [security.threat] };
  }

  if (value.length === 0) {
    setFeedback('filename', false, '✗ File name is required');
    updateSummary();
    return { valid: false, value, errors: ['File name is required'] };
  }

  // ── Hidden file check (Unix: .htaccess, .env, etc.) ────────
  if (value.startsWith('.')) {
    const msg = '✗ File name cannot start with "." — hidden files are not permitted';
    setFeedback('filename', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Path separator check ────────────────────────────────────
  if (/[/\\]/.test(value)) {
    const msg = '✗ File name cannot contain "/" or "\\" — path traversal not permitted';
    setFeedback('filename', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Space check ─────────────────────────────────────────────
  if (/\s/.test(value)) {
    const msg = '✗ File name cannot contain spaces — use underscore "_" or hyphen "-" instead';
    setFeedback('filename', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Double-extension check (security — before primary regex) ─
  // Catches "malware.pdf.exe" — L₃ ∩ ¬(Σ*·\.·Σ+·\.·Σ+)
  if (/\.\w+\.\w+/.test(value)) {
    const msg = '✗ Double-extension attack detected (e.g. "file.pdf.exe") — not permitted';
    setFeedback('filename', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Extension presence check ─────────────────────────────────
  const ext = getExtension(value);
  if (!ext) {
    const msg = '✗ File name must have an extension (e.g. report.pdf)';
    setFeedback('filename', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Extension whitelist check (before primary regex — clearer msg) ─
  const extNoDot = ext.slice(1); // Remove the leading dot
  if (!LIMITS.ALLOWED_EXTENSIONS.includes(extNoDot)) {
    if (LIMITS.BLOCKED_EXTENSIONS.includes(extNoDot)) {
      const msg = `✗ Extension ".${extNoDot}" is a dangerous file type — blocked`;
    } else {
      const msg = `✗ Extension "${ext}" not allowed — use: .${LIMITS.ALLOWED_EXTENSIONS.join(', .')}`;
    }
    const isBlocked = LIMITS.BLOCKED_EXTENSIONS.includes(extNoDot);
    const msg = isBlocked
      ? `✗ Extension "${ext}" is a blocked executable type`
      : `✗ Extension "${ext}" not permitted — allowed: .${LIMITS.ALLOWED_EXTENSIONS.join(', .')}`;
    setFeedback('filename', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Base name length check ───────────────────────────────────
  const baseName = value.slice(0, value.lastIndexOf('.'));
  if (baseName.length > LIMITS.FILE_NAME_MAX) {
    const msg = `✗ Base name too long — ${baseName.length} chars (max ${LIMITS.FILE_NAME_MAX})`;
    setFeedback('filename', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }
  if (baseName.length === 0) {
    const msg = '✗ Base name cannot be empty — provide a name before the extension';
    setFeedback('filename', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Primary regex (full formal validation) ──────────────────
  // L₃ = { w.e | w ∈ [a-zA-Z0-9_\-]{1,50}, e ∈ {jpg|jpeg|png|pdf|docx|txt} }
  if (!PATTERNS.FILE_NAME.test(value)) {
    const msg = '✗ File name contains invalid characters — use only letters, digits, underscore, or hyphen';
    setFeedback('filename', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  setFeedback('filename', true, `✓ Valid file name — "${sanitizeForDisplay(value)}"`);
  updateSummary();
  return { valid: true, value, errors: [] };
}

/**
 * Validates the File Extension field.
 *
 * Formal language:
 *   Σ  = { ., a–z, A–Z, 0–9 }
 *   L₄ = L_whitelist ∩ ¬L_blocklist
 *   where:
 *     L_whitelist = { .e | e ∈ {jpg,jpeg,png,pdf,docx,txt} }
 *     L_blocklist = { .e | e ∈ {exe,bat,sh,cmd,vbs,ps1,...} }
 *   Both are finite sets (trivially regular).
 *   Regular languages closed under ∩ and ¬ → L₄ is regular.
 *
 * Rules enforced:
 *   ✓ Must begin with a dot
 *   ✓ Extension body: alphanumeric only, 2–10 chars
 *   ✓ Must be in whitelist
 *   ✓ Must NOT be in blocklist (executable types)
 *
 * @param   {HTMLInputElement} input - The file extension input element
 * @returns {{ valid: boolean, value: string, errors: string[] }}
 */
function validateFileType(input) {
  const raw   = input.value;
  const value = raw.trim().toLowerCase();

  if (value.length === 0) {
    setFeedback('filetype', false, '✗ File extension is required (e.g. .pdf)');
    updateSummary();
    return { valid: false, value, errors: ['Extension required'] };
  }

  // ── Must start with a dot ───────────────────────────────────
  if (!value.startsWith('.')) {
    const msg = `✗ Extension must start with a dot — did you mean ".${value}"?`;
    setFeedback('filetype', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Blocklist check first (security priority) ───────────────
  // Formally: value ∈ L_blocklist → reject
  if (PATTERNS.FILE_EXT_BLOCKLIST.test(value)) {
    const msg = `✗ "${value}" is a dangerous executable extension — permanently blocked`;
    setFeedback('filetype', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Whitelist check (primary regex) ─────────────────────────
  // Formally: value ∈ L_whitelist = { .jpg, .jpeg, .png, .pdf, .docx, .txt }
  if (!PATTERNS.FILE_EXT_WHITELIST.test(value)) {
    const extBody = value.slice(1);
    const suggestion = LIMITS.ALLOWED_EXTENSIONS.find(e => e.startsWith(extBody.slice(0, 2)));
    const hintPart = suggestion ? ` — did you mean ".${suggestion}"?` : '';
    const msg = `✗ "${value}" not permitted${hintPart}. Allowed: .${LIMITS.ALLOWED_EXTENSIONS.join(', .')}`;
    setFeedback('filetype', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── All checks passed ────────────────────────────────────────
  setFeedback('filetype', true, `✓ "${value}" is a permitted file extension`);
  updateSummary();
  return { valid: true, value, errors: [] };
}

/**
 * Validates the File Size field.
 *
 * Formal language:
 *   Σ  = { 0–9, . }
 *   L₅ = { w ∈ Σ* | w = d⁺(\.d{1,2})?, 0 < parseFloat(w) ≤ 100 }
 *   The structural regex recognises the format; the numeric
 *   range check is a decidable O(1) semantic constraint.
 *
 * Rules enforced:
 *   ✓ Digits only (no letters, no symbols)
 *   ✓ At most one decimal point
 *   ✓ At most 2 decimal places
 *   ✓ Value strictly greater than 0
 *   ✓ Value ≤ 100 MB
 *   ✓ No leading zeros (e.g. "007" rejected — use "7")
 *   ✓ No trailing dot (e.g. "5." rejected)
 *
 * @param   {HTMLInputElement} input - The file size input element
 * @returns {{ valid: boolean, value: string, errors: string[] }}
 */
function validateFileSize(input) {
  const raw   = input.value;
  const value = raw.trim();

  if (value.length === 0) {
    setFeedback('filesize', false, '✗ File size is required (in MB, e.g. 4.75)');
    updateSummary();
    return { valid: false, value, errors: ['File size required'] };
  }

  // ── Leading zeros check (e.g. "007.5" should be "7.5") ─────
  // Exception: "0.5" is valid (leading zero before decimal)
  if (/^0\d/.test(value)) {
    const msg = `✗ Remove leading zero — write "${parseFloat(value)}" instead of "${value}"`;
    setFeedback('filesize', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Trailing dot check (e.g. "5." — incomplete decimal) ────
  if (value.endsWith('.')) {
    const msg = '✗ Incomplete decimal — add digits after the dot, or remove it';
    setFeedback('filesize', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Multiple dots check ──────────────────────────────────────
  const dotCount = (value.match(/\./g) || []).length;
  if (dotCount > 1) {
    const msg = '✗ Only one decimal point is allowed';
    setFeedback('filesize', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Primary regex: structural format check ──────────────────
  // Pattern: \d+(\.\d{1,2})?
  // Accepts: "4", "4.7", "4.75"
  // Rejects: "4.757", "4.7.5", "abc", ".75"
  if (!PATTERNS.FILE_SIZE.test(value)) {
    const msg = '✗ Invalid format — enter a number with up to 2 decimal places (e.g. 4.75)';
    setFeedback('filesize', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Decimal precision check (belt-and-suspenders) ───────────
  const decimals = decimalPlaces(value);
  if (decimals > LIMITS.FILE_SIZE_DECIMAL) {
    const msg = `✗ Too many decimal places (${decimals}) — maximum allowed is ${LIMITS.FILE_SIZE_DECIMAL}`;
    setFeedback('filesize', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Numeric range check ──────────────────────────────────────
  const numValue = parseFloat(value);

  if (isNaN(numValue)) {
    const msg = '✗ Not a valid number';
    setFeedback('filesize', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }
  if (numValue <= 0) {
    const msg = `✗ File size must be greater than 0 MB (minimum: ${LIMITS.FILE_SIZE_MIN} MB)`;
    setFeedback('filesize', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }
  if (numValue > LIMITS.FILE_SIZE_MAX) {
    const msg = `✗ File too large — ${numValue} MB exceeds maximum of ${LIMITS.FILE_SIZE_MAX} MB`;
    setFeedback('filesize', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── All checks passed ────────────────────────────────────────
  // Provide size-contextual feedback
  let sizeContext = '';
  if (numValue < 1)        sizeContext = '(small file)';
  else if (numValue < 10)  sizeContext = '(medium file)';
  else if (numValue < 50)  sizeContext = '(large file)';
  else                     sizeContext = '(very large — near limit)';

  setFeedback('filesize', true, `✓ Valid size — ${numValue} MB ${sizeContext}`);
  updateSummary();
  return { valid: true, value, errors: [] };
}

/**
 * Validates the Description field.
 *
 * Formal language:
 *   Σ  = { a–z, A–Z, 0–9, space, ., ,, !, ?, ', - }
 *   L₆ = { w ∈ Σ* | 10 ≤ |w| ≤ 300, w ∉ (whitespace-only strings) }
 *   By complement+intersection closure: L₆ is regular.
 *   DFA requires 301 counting states for length bounds.
 *
 * Rules enforced:
 *   ✓ Minimum 10 characters
 *   ✓ Maximum 300 characters
 *   ✓ Not whitespace-only (negative lookahead)
 *   ✓ Only safe characters — blocks XSS vectors < > & " / = { }
 *   ✓ Security pre-screen passes
 *   ✓ Real character count shown to user
 *
 * @param   {HTMLInputElement|HTMLTextAreaElement} input
 * @returns {{ valid: boolean, value: string, errors: string[] }}
 */
function validateDescription(input) {
  const raw   = input.value; // Do NOT trim — spaces are valid content
  const value = raw;
  const len   = value.length;

  // ── Security pre-screen ────────────────────────────────────
  const security = securityPreScreen(value);
  if (!security.safe) {
    setFeedback('description', false, `⚠ Security: ${security.threat}`);
    updateSummary();
    return { valid: false, value, errors: [security.threat] };
  }

  // ── Empty check ─────────────────────────────────────────────
  if (len === 0) {
    setFeedback('description', false, '✗ Description is required');
    updateSummary();
    return { valid: false, value, errors: ['Description is required'] };
  }

  // ── Whitespace-only check (before length — specific msg) ────
  // Formally: w ∉ \s* — complement of whitespace-only language
  if (/^\s+$/.test(value)) {
    const msg = '✗ Description cannot be whitespace only — please write meaningful text';
    setFeedback('description', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Length checks ────────────────────────────────────────────
  if (len < LIMITS.DESC_MIN) {
    const remaining = LIMITS.DESC_MIN - len;
    const msg = `✗ Too short — ${len}/${LIMITS.DESC_MIN} chars (need ${remaining} more)`;
    setFeedback('description', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }
  if (len > LIMITS.DESC_MAX) {
    const excess = len - LIMITS.DESC_MAX;
    const msg = `✗ Too long — ${len}/${LIMITS.DESC_MAX} chars (remove ${excess} characters)`;
    setFeedback('description', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Character class check (detect specific forbidden chars) ─
  const invalidChars = value.match(/[^a-zA-Z0-9\s.,!?'\-]/g);
  if (invalidChars) {
    const unique = [...new Set(invalidChars)]
      .map(c => `"${sanitizeForDisplay(c)}"`)
      .slice(0, 5) // Show at most 5 offending chars
      .join(', ');
    const msg = `✗ Invalid character(s): ${unique} — only letters, digits, spaces and . , ! ? ' - allowed`;
    setFeedback('description', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Primary regex (full formal validation) ──────────────────
  // L₆ = { w ∈ Σ* | 10 ≤ |w| ≤ 300, w ∉ \s* }
  if (!PATTERNS.DESCRIPTION.test(value)) {
    const msg = '✗ Description contains invalid content — please review your input';
    setFeedback('description', false, msg);
    updateSummary();
    return { valid: false, value, errors: [msg] };
  }

  // ── Progressive length feedback ──────────────────────────────
  const remaining = LIMITS.DESC_MAX - len;
  const pct = Math.round((len / LIMITS.DESC_MAX) * 100);
  let warnLevel = 'success';
  let icon = '✓';
  let note = '';
  if (remaining < 30) {
    warnLevel = 'warning';
    icon = '⚠';
    note = ` — ${remaining} chars remaining`;
  }
  setFeedback('description', true, `${icon} Valid description — ${len}/${LIMITS.DESC_MAX} chars${note}`, warnLevel);
  updateSummary();
  return { valid: true, value, errors: [] };
}

/**
 * Validates an actual File Upload (HTMLInputElement[type=file]).
 * Performs client-side validation of the uploaded file object.
 *
 * Validation layers:
 *   1. Filename structure  — delegates to validateFileName logic
 *   2. Extension whitelist — PATTERNS.FILE_EXT_WHITELIST
 *   3. Extension blocklist — PATTERNS.FILE_EXT_BLOCKLIST
 *   4. MIME type whitelist — LIMITS.ALLOWED_MIME_TYPES
 *   5. File size limit     — LIMITS.UPLOAD_MAX_BYTES (100 MB)
 *   6. File size min       — must be > 0 bytes (not empty)
 *   7. Double-extension    — PATTERNS.FILE_NAME check
 *
 * Note: Client-side MIME validation is informational — the
 * server must independently validate MIME type and content.
 *
 * @param   {HTMLInputElement} input - file input element
 * @returns {{ valid: boolean, file: File|null, errors: string[] }}
 */
function handleFileUpload(input) {
  const file    = input.files && input.files[0];
  const dropEl  = document.getElementById('fileDrop');
  const fbEl    = document.getElementById('fb-fileupload');

  if (!file) {
    if (fbEl) { fbEl.className = 'field-feedback'; fbEl.textContent = ''; }
    if (dropEl) dropEl.style.borderColor = '';
    return { valid: false, file: null, errors: ['No file selected'] };
  }

  const errors  = [];
  const name    = file.name;
  const sizeMB  = file.size / (1024 * 1024);
  const ext     = getExtension(name);

  // ── Empty file check ─────────────────────────────────────────
  if (file.size === 0) {
    errors.push('File is empty (0 bytes)');
  }

  // ── Size limit check ─────────────────────────────────────────
  if (file.size > LIMITS.UPLOAD_MAX_BYTES) {
    errors.push(`File too large — ${sizeMB.toFixed(2)} MB exceeds ${LIMITS.FILE_SIZE_MAX} MB limit`);
  }

  // ── Null byte in filename ────────────────────────────────────
  if (PATTERNS.NULL_BYTE.test(name)) {
    errors.push('Null byte detected in filename — rejected');
  }

  // ── Double-extension check ───────────────────────────────────
  if (/\.\w+\.\w+/.test(name)) {
    errors.push(`Double-extension attack detected — "${name}" rejected`);
  }

  // ── Extension checks ─────────────────────────────────────────
  if (!ext) {
    errors.push('File has no extension');
  } else {
    if (PATTERNS.FILE_EXT_BLOCKLIST.test(ext)) {
      errors.push(`Extension "${ext}" is a blocked executable type`);
    } else if (!PATTERNS.FILE_EXT_WHITELIST.test(ext)) {
      errors.push(`Extension "${ext}" not allowed — use .${LIMITS.ALLOWED_EXTENSIONS.join(', .')}`);
    }
  }

  // ── MIME type check ──────────────────────────────────────────
  if (file.type && !LIMITS.ALLOWED_MIME_TYPES.includes(file.type)) {
    errors.push(`MIME type "${file.type}" not permitted`);
  }

  const isValid = errors.length === 0;

  // ── UI feedback ──────────────────────────────────────────────
  if (fbEl) {
    fbEl.className = `field-feedback ${isValid ? 'ok' : 'err'}`;
    fbEl.textContent = isValid
      ? `✓ "${name}" accepted — ${sizeMB.toFixed(2)} MB`
      : `✗ ${errors[0]}`; // Show first error
  }
  if (dropEl) {
    dropEl.style.borderColor = isValid ? 'var(--green)' : 'var(--red)';
  }

  // ── Auto-fill related fields ─────────────────────────────────
  if (isValid) {
    _autoFillFromUpload(name, sizeMB);
  }

  return { valid: isValid, file: isValid ? file : null, errors };
}

/**
 * Auto-fills filename, extension, and size fields from a
 * successfully uploaded file. Only fills if field is currently empty.
 *
 * @param {string} filename - The uploaded file's name
 * @param {number} sizeMB   - File size in megabytes
 * @private
 */
function _autoFillFromUpload(filename, sizeMB) {
  const fnInput = document.getElementById('filename');
  if (fnInput && !fnInput.value.trim()) {
    fnInput.value = filename;
    validateFileName(fnInput);
  }

  const ftInput = document.getElementById('filetype');
  if (ftInput && !ftInput.value.trim()) {
    const ext = getExtension(filename);
    if (ext) {
      ftInput.value = ext;
      validateFileType(ftInput);
    }
  }

  const fsInput = document.getElementById('filesize');
  if (fsInput && !fsInput.value.trim()) {
    fsInput.value = sizeMB.toFixed(2);
    validateFileSize(fsInput);
  }
}

/* ============================================================
   SECTION 6 — FORM CONTROLLER
   Orchestrates all validators and controls form submission.
   ============================================================ */

/**
 * Runs all validators simultaneously and returns a summary
 * of the form's validation state.
 *
 * @returns {{ allValid: boolean, results: Object, failCount: number }}
 */
function validateAll() {
  const results = {
    username:    validateUsername   (document.getElementById('username')),
    email:       validateEmail      (document.getElementById('email')),
    filename:    validateFileName   (document.getElementById('filename')),
    filetype:    validateFileType   (document.getElementById('filetype')),
    filesize:    validateFileSize   (document.getElementById('filesize')),
    description: validateDescription(document.getElementById('description')),
  };

  const allValid  = Object.values(results).every(r => r.valid);
  const failCount = Object.values(results).filter(r => !r.valid).length;

  return { allValid, results, failCount };
}

/**
 * Handles form submission. Prevents default behaviour, runs
 * validateAll(), and either shows success or highlights errors.
 *
 * @param   {Event} event - The form submit event
 * @returns {boolean}     - Always returns false (prevents native submit)
 */
function handleSubmit(event) {
  event.preventDefault();

  // Run all validators (they update the UI individually)
  const { allValid, results, failCount } = validateAll();

  if (allValid) {
    showToast('✓ All 6 fields valid — secure upload request accepted!', true);

    // Brief visual celebration then reset (demo behaviour)
    const btn = document.querySelector('.btn-submit');
    if (btn) {
      btn.style.background = 'linear-gradient(135deg, var(--green), #1aaf5d)';
      setTimeout(() => { btn.style.background = ''; }, 2000);
    }
  } else {
    const fieldWord = failCount === 1 ? 'field' : 'fields';
    showToast(`✗ ${failCount} ${fieldWord} invalid — scroll up and fix highlighted errors`, false);

    // Scroll to first invalid field
    const firstInvalid = document.querySelector('input.invalid, textarea.invalid');
    if (firstInvalid) {
      firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
      firstInvalid.focus();
    }
  }

  return false;
}

/**
 * Resets the entire form: clears all values, removes all
 * validation classes, resets feedback messages.
 */
function resetForm() {
  const form = document.getElementById('mainForm');
  if (!form) return;

  form.reset();

  const allFields = ['username', 'email', 'filename', 'filetype', 'filesize', 'description'];
  allFields.forEach(id => clearFeedback(id));

  // Reset file upload UI
  const dropEl = document.getElementById('fileDrop');
  if (dropEl) dropEl.style.borderColor = '';

  const fbUpload = document.getElementById('fb-fileupload');
  if (fbUpload) { fbUpload.textContent = ''; fbUpload.className = 'field-feedback'; }

  updateSummary();
  showToast('Form reset — all fields cleared', true);
}

/* ============================================================
   SECTION 7 — LIVE REGEX TESTER MODULE
   Allows the evaluator to test any pattern live.
   All patterns from PATTERNS object are exposed.
   ============================================================ */

/**
 * Object mapping UI select option values to their
 * corresponding pattern(s) and extra validation logic.
 * Keeps the tester in sync with PATTERNS automatically.
 */
const TESTER_CONFIG = Object.freeze({
  username: {
    pattern: PATTERNS.USERNAME,
    label: 'Username',
    extra: (v) => {
      if (v.length < LIMITS.USERNAME_MIN) return `Too short (${v.length} < ${LIMITS.USERNAME_MIN})`;
      if (v.length > LIMITS.USERNAME_MAX) return `Too long (${v.length} > ${LIMITS.USERNAME_MAX})`;
      return null;
    },
  },
  email: {
    pattern: PATTERNS.EMAIL,
    label: 'Email Address',
    extra: null,
  },
  filename: {
    pattern: PATTERNS.FILE_NAME,
    label: 'File Name',
    extra: null,
  },
  filetype: {
    pattern: PATTERNS.FILE_EXT_WHITELIST,
    label: 'File Extension (whitelist)',
    extra: (v) => PATTERNS.FILE_EXT_BLOCKLIST.test(v) ? 'Also blocked by blocklist' : null,
  },
  filesize: {
    pattern: PATTERNS.FILE_SIZE,
    label: 'File Size',
    extra: (v) => {
      const n = parseFloat(v);
      if (n <= 0)                   return `Out of range — must be > 0`;
      if (n > LIMITS.FILE_SIZE_MAX) return `Out of range — ${n} > ${LIMITS.FILE_SIZE_MAX}`;
      return null;
    },
  },
  description: {
    pattern: PATTERNS.DESCRIPTION,
    label: 'Description',
    extra: null,
  },
});

/**
 * Runs the live regex tester. Called on every keypress in
 * the tester input or change in the pattern selector.
 */
function runTester() {
  const key      = document.getElementById('testerPattern')?.value;
  const rawVal   = document.getElementById('testerInput')?.value;
  const resultEl = document.getElementById('testerResult');
  if (!resultEl) return;

  if (!key || !rawVal) {
    resultEl.className = 'tester-result idle';
    resultEl.textContent = '—';
    return;
  }

  const config = TESTER_CONFIG[key];
  if (!config) return;

  const value    = rawVal.trim();
  const matches  = config.pattern.test(value);
  const extraMsg = config.extra ? config.extra(value) : null;

  // Extra checks can override a regex match
  const finalMatch = matches && !extraMsg;

  resultEl.className  = `tester-result ${finalMatch ? 'match' : 'nomatch'}`;
  resultEl.textContent = finalMatch
    ? `✓ MATCH  [${config.label}]`
    : `✗ NO MATCH${extraMsg ? ` — ${extraMsg}` : ''}`;
}

/* ============================================================
   SECTION 8 — EVENT BINDING & INITIALISATION
   Attaches all event listeners after DOM is ready.
   Uses DOMContentLoaded to avoid race conditions.
   ============================================================ */

/**
 * Master initialisation function.
 * Called once DOM is fully loaded.
 */
function initValidation() {

  // ── Field → validator mapping ─────────────────────────────
  const FIELD_VALIDATORS = {
    username:    validateUsername,
    email:       validateEmail,
    filename:    validateFileName,
    filetype:    validateFileType,
    filesize:    validateFileSize,
    description: validateDescription,
  };

  // ── Attach oninput validators ─────────────────────────────
  Object.entries(FIELD_VALIDATORS).forEach(([id, validator]) => {
    const el = document.getElementById(id);
    if (!el) return;

    // oninput — validate on every keystroke (real-time)
    el.addEventListener('input', () => validator(el));

    // onblur — validate on leaving field (catches paste + tab)
    el.addEventListener('blur', () => {
      if (el.value.trim()) validator(el); // Only validate if not empty on blur
    });

    // onfocus — show neutral placeholder message
    el.addEventListener('focus', () => {
      // Only show hint if field has not been touched yet
      if (!el.classList.contains('valid') && !el.classList.contains('invalid')) {
        const fb = document.getElementById(`fb-${id}`);
        if (fb && fb.textContent === '') {
          // Optionally show a hint on focus
        }
      }
    });
  });

  // ── File upload handler ────────────────────────────────────
  const fileInput = document.getElementById('fileupload');
  if (fileInput) {
    fileInput.addEventListener('change', () => handleFileUpload(fileInput));
  }

  // ── Drag-and-drop visual feedback ─────────────────────────
  const dropZone = document.getElementById('fileDrop');
  if (dropZone) {
    dropZone.addEventListener('dragover', (e) => {
      e.preventDefault();
      dropZone.classList.add('drag');
    });
    dropZone.addEventListener('dragleave', () => {
      dropZone.classList.remove('drag');
    });
    dropZone.addEventListener('drop', (e) => {
      e.preventDefault();
      dropZone.classList.remove('drag');
      if (fileInput && e.dataTransfer.files.length) {
        // Assign dropped files to the file input
        const dt = new DataTransfer();
        dt.items.add(e.dataTransfer.files[0]);
        fileInput.files = dt.files;
        handleFileUpload(fileInput);
      }
    });
  }

  // ── Form submit ────────────────────────────────────────────
  const form = document.getElementById('mainForm');
  if (form) {
    form.addEventListener('submit', handleSubmit);
  }

  // ── Reset button ───────────────────────────────────────────
  const resetBtn = document.getElementById('resetBtn');
  if (resetBtn) {
    resetBtn.addEventListener('click', resetForm);
  }

  // ── Live tester ────────────────────────────────────────────
  const testerPattern = document.getElementById('testerPattern');
  const testerInput   = document.getElementById('testerInput');
  if (testerPattern) testerPattern.addEventListener('change', runTester);
  if (testerInput)   testerInput.addEventListener('input',  runTester);

  // ── Regex card accordion (§2 section) ─────────────────────
  document.querySelectorAll('.rc-head').forEach(head => {
    head.addEventListener('click', () => {
      const card = head.closest('.regex-card');
      if (card) card.classList.toggle('open');
    });
  });

  // ── Code copy buttons ──────────────────────────────────────
  document.querySelectorAll('.code-copy').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('onclick')?.match(/'([^']+)'/)?.[1];
      if (!targetId) return;
      const el = document.getElementById(targetId);
      if (!el) return;
      navigator.clipboard.writeText(el.innerText).then(() => {
        btn.textContent = 'Copied!';
        showToast('✓ Code copied to clipboard', true);
        setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
      }).catch(() => {
        showToast('✗ Copy failed — please select and copy manually', false);
      });
    });
  });

  // ── Initial summary state ──────────────────────────────────
  updateSummary();

  console.log(
    '%c[TOC Validator] Initialised successfully — 6 field validators active',
    'color:#00e5ff; font-family:monospace; font-weight:bold;'
  );
}

/* ============================================================
   SECTION 9 — PUBLIC API
   Expose functions that index.html's inline handlers reference.
   Keeps the global namespace minimal.
   ============================================================ */

// Called by oninput attributes in HTML (legacy compat + explicit binding)
window.validateUsername    = validateUsername;
window.validateEmail       = validateEmail;
window.validateFileName    = validateFileName;
window.validateFileType    = validateFileType;
window.validateFileSize    = validateFileSize;
window.validateDescription = validateDescription;
window.handleFileUpload    = handleFileUpload;
window.handleSubmit        = handleSubmit;
window.resetForm           = resetForm;
window.runTester           = runTester;
window.toggleCard          = function(head) {
  const card = head.closest('.regex-card');
  if (card) card.classList.toggle('open');
};
window.copyCode            = function(id) {
  const el = document.getElementById(id);
  if (!el) return;
  navigator.clipboard.writeText(el.innerText).then(() => {
    showToast('✓ Code copied to clipboard', true);
  });
};

// Expose PATTERNS and LIMITS for browser console inspection by evaluator
window.TOC_PATTERNS = PATTERNS;
window.TOC_LIMITS   = LIMITS;
window.TOC_validateAll = validateAll;

/* ============================================================
   SECTION 10 — BOOT
   Defer initialisation until DOM is fully parsed.
   ============================================================ */

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initValidation);
} else {
  // DOM already ready (script loaded with defer or at bottom of <body>)
  initValidation();
}

/* ============================================================
   END OF validation.js
   ============================================================
   Summary of regex patterns:
     F1 USERNAME    : ^(?![0-9]+$)[a-zA-Z0-9_]{3,20}$
     F2 EMAIL       : ^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$
     F3 FILE NAME   : ^(?!.*\.\w+\.\w+)[a-zA-Z0-9_\-]{1,50}\.(jpg|jpeg|png|pdf|docx|txt)$
     F4 EXT WLIST   : ^\.(jpg|jpeg|png|pdf|docx|txt)$
     F4 EXT BLIST   : ^\.(exe|bat|sh|cmd|vbs|ps1|msi|dll|php|js|...)$
     F5 FILE SIZE   : ^\d+(\.\d{1,2})?$  + range 0 < n <= 100
     F6 DESCRIPTION : ^(?!\s*$)[a-zA-Z0-9\s.,!?'\-]{10,300}$
   ============================================================ */