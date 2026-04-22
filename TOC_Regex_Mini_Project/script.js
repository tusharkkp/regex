/**
 * ============================================
 * Secure File Upload System - Validation Logic
 * Theory of Computation Mini Project
 * Author: Tushar Kaldate | PRN: 202401040191
 * ============================================
 *
 * Each validation function uses formally defined
 * regular expressions mapped to regular languages.
 * All regex patterns use anchors, quantifiers,
 * character classes, groups, and lookaheads.
 */

// ─────────────────────────────────────────────
// §1  REGEX PATTERN DEFINITIONS
// ─────────────────────────────────────────────

/**
 * USERNAME REGEX
 * Pattern: ^(?=.{3,20}$)[a-zA-Z][a-zA-Z0-9_]*$
 *
 * Breakdown:
 *   ^               → Start anchor
 *   (?=.{3,20}$)    → Lookahead: total length must be 3–20
 *   [a-zA-Z]        → First character must be a letter
 *   [a-zA-Z0-9_]*   → Remaining: letters, digits, underscores
 *   $               → End anchor
 *
 * Formal Language:
 *   L = { w ∈ Σ* | |w| ∈ [3,20], w₁ ∈ [a-zA-Z],
 *         wᵢ ∈ [a-zA-Z0-9_] for i > 1 }
 *   Σ = { a-z, A-Z, 0-9, _ }
 */
const REGEX_USERNAME = /^(?=.{3,20}$)[a-zA-Z][a-zA-Z0-9_]*$/;

/**
 * EMAIL REGEX
 * Pattern: ^(?=.{5,254}$)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$
 *
 * Breakdown:
 *   ^                       → Start anchor
 *   (?=.{5,254}$)           → Lookahead: length between 5 and 254
 *   [a-zA-Z0-9._%+-]+       → Local part: alphanumerics + special chars
 *   @                       → Literal @ separator
 *   [a-zA-Z0-9.-]+          → Domain name
 *   \.                      → Literal dot before TLD
 *   [a-z]{2,}               → TLD: at least 2 lowercase letters
 *   $                       → End anchor
 *
 * Formal Language:
 *   L = { w ∈ Σ* | w = local@domain.tld,
 *         local ∈ [a-zA-Z0-9._%+-]+,
 *         domain ∈ [a-zA-Z0-9.-]+,
 *         tld ∈ [a-z]{2,} }
 *   Σ = { a-z, A-Z, 0-9, ., _, %, +, -, @ }
 */
const REGEX_EMAIL = /^(?=.{5,254}$)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$/;

/**
 * FILE NAME REGEX
 * Pattern: ^(?=.{1,100}$)[a-zA-Z0-9][a-zA-Z0-9_-]*\.(jpg|jpeg|png|gif|pdf|docx?|txt)$
 *
 * Breakdown:
 *   ^                        → Start anchor
 *   (?=.{1,100}$)            → Lookahead: total length 1–100
 *   [a-zA-Z0-9]              → Must start with alphanumeric
 *   [a-zA-Z0-9_-]*           → Body: letters, digits, underscores, hyphens
 *   \.                       → Literal dot before extension
 *   (jpg|jpeg|png|gif|pdf|docx?|txt) → Allowed file extensions
 *   $                        → End anchor
 *
 * Formal Language:
 *   L = { w ∈ Σ* | w = name.ext, |w| ≤ 100,
 *         name ∈ [a-zA-Z0-9][a-zA-Z0-9_-]*,
 *         ext ∈ {jpg, jpeg, png, gif, pdf, doc, docx, txt} }
 *   Σ = { a-z, A-Z, 0-9, _, -, . }
 */
const REGEX_FILENAME = /^(?=.{1,100}$)[a-zA-Z0-9][a-zA-Z0-9_-]*\.(jpg|jpeg|png|gif|pdf|docx?|txt)$/i;

/**
 * FILE TYPE REGEX (with negative lookahead to block dangerous extensions)
 * Pattern: ^(?!.*\.(exe|bat|sh|cmd|msi|dll|com|scr|vbs|ps1)$).+\.[a-zA-Z]{2,5}$
 *
 * Breakdown:
 *   ^                           → Start anchor
 *   (?!.*\.(exe|bat|sh|...))    → Negative lookahead: block dangerous extensions
 *   .+                          → At least one character for filename
 *   \.                          → Literal dot
 *   [a-zA-Z]{2,5}              → Extension: 2–5 letters
 *   $                           → End anchor
 *
 * Formal Language:
 *   L = { w ∈ Σ* | w = name.ext,
 *         ext ∉ {exe, bat, sh, cmd, msi, dll, com, scr, vbs, ps1},
 *         ext ∈ [a-zA-Z]{2,5} }
 *   Σ = { a-z, A-Z, 0-9, _, -, . }
 */
const REGEX_FILETYPE = /^(?!.*\.(exe|bat|sh|cmd|msi|dll|com|scr|vbs|ps1)$).+\.[a-zA-Z]{2,5}$/i;

/**
 * FILE SIZE REGEX
 * Pattern: ^(?=.{1,10}$)([1-9]\d{0,5}|0)(\.\d{1,2})?\s?(KB|MB|GB)$
 *
 * Breakdown:
 *   ^                     → Start anchor
 *   (?=.{1,10}$)          → Lookahead: reasonable length limit
 *   ([1-9]\d{0,5}|0)      → Number: 0 or 1–999999 (no leading zeros)
 *   (\.\d{1,2})?          → Optional decimal with up to 2 places
 *   \s?                   → Optional space
 *   (KB|MB|GB)            → Unit: KB, MB, or GB
 *   $                     → End anchor
 *
 * Formal Language:
 *   L = { w ∈ Σ* | w = n[.d] unit,
 *         n ∈ {0} ∪ [1-9][0-9]{0,5},
 *         d ∈ [0-9]{1,2} (optional),
 *         unit ∈ {KB, MB, GB} }
 *   Σ = { 0-9, ., K, M, G, B, space }
 */
const REGEX_FILESIZE = /^([1-9]\d{0,5}|0)(\.\d{1,2})?\s?(KB|MB|GB)$/i;

// Additional: numeric value ≤ 100 MB
const REGEX_FILESIZE_LIMIT = /^([1-9]\d{0,1}(\.\d{1,2})?|100(\.0{1,2})?)\s?MB$|^(\d{1,6}(\.\d{1,2})?)\s?KB$|^(0(\.\d{1,2})?)\s?GB$/i;

/**
 * DESCRIPTION REGEX
 * Pattern: ^(?=.{10,500}$)(?=.*[a-zA-Z]{3,})[a-zA-Z0-9\s.,;:!?'"-]+$
 *
 * Breakdown:
 *   ^                          → Start anchor
 *   (?=.{10,500}$)             → Lookahead: length between 10 and 500
 *   (?=.*[a-zA-Z]{3,})         → Lookahead: must contain a word (≥3 letters)
 *   [a-zA-Z0-9\s.,;:!?'"-]+   → Allowed characters
 *   $                          → End anchor
 *
 * Formal Language:
 *   L = { w ∈ Σ* | 10 ≤ |w| ≤ 500,
 *         ∃ substring u in w: u ∈ [a-zA-Z]{3,},
 *         wᵢ ∈ [a-zA-Z0-9 .,;:!?'"-] }
 *   Σ = { a-z, A-Z, 0-9, space, ., ,, ;, :, !, ?, ', ", - }
 */
const REGEX_DESCRIPTION = /^(?=.{10,500}$)(?=.*[a-zA-Z]{3,})[a-zA-Z0-9\s.,;:!?'"\-]+$/;


// ─────────────────────────────────────────────
// §2  VALIDATION STATE
// ─────────────────────────────────────────────

const validationState = {
  username: false,
  email: false,
  filename: false,
  filetype: false,
  filesize: false,
  description: false
};


// ─────────────────────────────────────────────
// §3  UTILITY FUNCTIONS
// ─────────────────────────────────────────────

/**
 * Set visual feedback on a form field.
 * @param {string} fieldId   - The input element ID
 * @param {boolean} isValid  - Validation result
 * @param {string} message   - Feedback message
 */
function setFeedback(fieldId, isValid, message) {
  const input = document.getElementById(fieldId);
  const feedback = document.getElementById(fieldId + '-feedback');

  if (!input || !feedback) return;

  // Remove existing classes
  input.classList.remove('valid', 'invalid');
  feedback.classList.remove('success', 'error');

  if (input.value.trim() === '') {
    // Empty — reset to neutral
    feedback.innerHTML = '';
    return;
  }

  if (isValid) {
    input.classList.add('valid');
    feedback.classList.add('success');
    feedback.innerHTML = '<span class="feedback-icon">✓</span> ' + message;
  } else {
    input.classList.add('invalid');
    feedback.classList.add('error');
    feedback.innerHTML = '<span class="feedback-icon">✗</span> ' + message;
  }
}

/**
 * Check if ALL fields are valid to enable/disable submit button.
 */
function updateSubmitButton() {
  const btn = document.getElementById('submit-btn');
  if (!btn) return;
  const allValid = Object.values(validationState).every(v => v);
  btn.disabled = !allValid;
}


// ─────────────────────────────────────────────
// §4  INDIVIDUAL VALIDATION FUNCTIONS
// ─────────────────────────────────────────────

/**
 * Validate Username
 * Regex: ^(?=.{3,20}$)[a-zA-Z][a-zA-Z0-9_]*$
 * Must start with letter, 3-20 chars, alphanumeric + underscore
 */
function validateUsername() {
  const val = document.getElementById('username').value;
  const isValid = REGEX_USERNAME.test(val);
  validationState.username = isValid;

  if (val.trim() === '') {
    setFeedback('username', false, '');
  } else if (!isValid) {
    // Provide specific error feedback
    if (val.length < 3) {
      setFeedback('username', false, 'Too short — minimum 3 characters');
    } else if (val.length > 20) {
      setFeedback('username', false, 'Too long — maximum 20 characters');
    } else if (!/^[a-zA-Z]/.test(val)) {
      setFeedback('username', false, 'Must start with a letter');
    } else {
      setFeedback('username', false, 'Only letters, digits, and underscores allowed');
    }
  } else {
    setFeedback('username', true, 'Valid username');
  }
  updateSubmitButton();
}

/**
 * Validate Email
 * Regex: ^(?=.{5,254}$)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-z]{2,}$
 * Standard email format with lookahead length constraint
 */
function validateEmail() {
  const val = document.getElementById('email').value;
  const isValid = REGEX_EMAIL.test(val);
  validationState.email = isValid;

  if (val.trim() === '') {
    setFeedback('email', false, '');
  } else if (!isValid) {
    if (!val.includes('@')) {
      setFeedback('email', false, 'Missing @ symbol');
    } else if (!/\.[a-z]{2,}$/.test(val)) {
      setFeedback('email', false, 'Invalid domain or TLD');
    } else {
      setFeedback('email', false, 'Invalid email format');
    }
  } else {
    setFeedback('email', true, 'Valid email address');
  }
  updateSubmitButton();
}

/**
 * Validate File Name
 * Regex: ^(?=.{1,100}$)[a-zA-Z0-9][a-zA-Z0-9_-]*\.(jpg|jpeg|png|gif|pdf|docx?|txt)$
 * Alphanumeric start, allowed extensions only
 */
function validateFileName() {
  const val = document.getElementById('filename').value;
  const isValid = REGEX_FILENAME.test(val);
  validationState.filename = isValid;

  if (val.trim() === '') {
    setFeedback('filename', false, '');
  } else if (!isValid) {
    if (!/\./.test(val)) {
      setFeedback('filename', false, 'Missing file extension');
    } else if (!/\.(jpg|jpeg|png|gif|pdf|docx?|txt)$/i.test(val)) {
      setFeedback('filename', false, 'Unsupported extension — use jpg, png, pdf, doc, txt');
    } else if (!/^[a-zA-Z0-9]/.test(val)) {
      setFeedback('filename', false, 'Must start with a letter or digit');
    } else {
      setFeedback('filename', false, 'Invalid characters in file name');
    }
  } else {
    setFeedback('filename', true, 'Valid file name');
  }
  updateSubmitButton();
}

/**
 * Validate File Type (extension safety)
 * Regex: ^(?!.*\.(exe|bat|sh|cmd|msi|dll|com|scr|vbs|ps1)$).+\.[a-zA-Z]{2,5}$
 * Uses NEGATIVE LOOKAHEAD to block dangerous extensions
 */
function validateFileType() {
  const val = document.getElementById('filetype').value;
  const isValid = REGEX_FILETYPE.test(val);
  validationState.filetype = isValid;

  if (val.trim() === '') {
    setFeedback('filetype', false, '');
  } else if (!isValid) {
    if (/\.(exe|bat|sh|cmd|msi|dll|com|scr|vbs|ps1)$/i.test(val)) {
      setFeedback('filetype', false, 'Blocked — executable/script files are not allowed');
    } else if (!/\.[a-zA-Z]{2,5}$/.test(val)) {
      setFeedback('filetype', false, 'Invalid extension format (2-5 letters)');
    } else {
      setFeedback('filetype', false, 'Invalid file type format');
    }
  } else {
    setFeedback('filetype', true, 'Safe file type ✓');
  }
  updateSubmitButton();
}

/**
 * Validate File Size
 * Regex: ^([1-9]\d{0,5}|0)(\.\d{1,2})?\s?(KB|MB|GB)$
 * Numeric value with unit, no leading zeros
 */
function validateFileSize() {
  const val = document.getElementById('filesize').value;
  const isValid = REGEX_FILESIZE.test(val);
  validationState.filesize = isValid;

  if (val.trim() === '') {
    setFeedback('filesize', false, '');
  } else if (!isValid) {
    if (!/\d/.test(val)) {
      setFeedback('filesize', false, 'Must contain a number');
    } else if (!/(KB|MB|GB)/i.test(val)) {
      setFeedback('filesize', false, 'Must include unit: KB, MB, or GB');
    } else if (/^0\d/.test(val)) {
      setFeedback('filesize', false, 'No leading zeros allowed');
    } else {
      setFeedback('filesize', false, 'Invalid format — example: 5.5 MB');
    }
  } else {
    // Additional check: warn if > 100MB
    const match = val.match(/^(\d+\.?\d*)\s?(KB|MB|GB)$/i);
    if (match) {
      const num = parseFloat(match[1]);
      const unit = match[2].toUpperCase();
      if (unit === 'GB' || (unit === 'MB' && num > 100)) {
        setFeedback('filesize', true, 'Valid but large file size (>100MB)');
        return;
      }
    }
    setFeedback('filesize', true, 'Valid file size');
  }
  updateSubmitButton();
}

/**
 * Validate Description
 * Regex: ^(?=.{10,500}$)(?=.*[a-zA-Z]{3,})[a-zA-Z0-9\s.,;:!?'"-]+$
 * 10-500 chars, must contain meaningful words, safe characters only
 */
function validateDescription() {
  const val = document.getElementById('description').value;
  const isValid = REGEX_DESCRIPTION.test(val);
  validationState.description = isValid;

  if (val.trim() === '') {
    setFeedback('description', false, '');
  } else if (!isValid) {
    if (val.length < 10) {
      setFeedback('description', false, 'Too short — minimum 10 characters');
    } else if (val.length > 500) {
      setFeedback('description', false, 'Too long — maximum 500 characters');
    } else if (!/[a-zA-Z]{3,}/.test(val)) {
      setFeedback('description', false, 'Must contain at least one word (3+ letters)');
    } else {
      setFeedback('description', false, 'Contains invalid special characters');
    }
  } else {
    const remaining = 500 - val.length;
    setFeedback('description', true, 'Valid description (' + remaining + ' chars remaining)');
  }
  updateSubmitButton();
}


// ─────────────────────────────────────────────
// §5  FORM SUBMISSION HANDLER
// ─────────────────────────────────────────────

/**
 * Handle form submission.
 * Prevents submission if any field is invalid.
 * Shows a results panel on success.
 */
function handleSubmit(event) {
  event.preventDefault();

  // Re-validate all fields
  validateUsername();
  validateEmail();
  validateFileName();
  validateFileType();
  validateFileSize();
  validateDescription();

  const allValid = Object.values(validationState).every(v => v);
  const resultsPanel = document.getElementById('results-panel');

  if (allValid) {
    resultsPanel.className = 'results-panel show success-panel';
    resultsPanel.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
        <span style="font-size:1.5rem;">✓</span>
        <strong style="font-size:1.1rem;">Upload Validated Successfully</strong>
      </div>
      <p style="color:var(--success);opacity:0.8;font-size:0.9rem;">
        All fields passed regex validation. The file upload request is ready for processing.
        In a production system, this data would now be sent to the server.
      </p>
      <div style="margin-top:16px;padding:14px;background:rgba(16,185,129,0.08);border-radius:8px;font-size:0.85rem;">
        <strong>Summary:</strong><br>
        Username: ${document.getElementById('username').value}<br>
        Email: ${document.getElementById('email').value}<br>
        File: ${document.getElementById('filename').value}<br>
        Type: ${document.getElementById('filetype').value}<br>
        Size: ${document.getElementById('filesize').value}
      </div>
    `;
  } else {
    const invalidFields = Object.entries(validationState)
      .filter(([, v]) => !v)
      .map(([k]) => k);

    resultsPanel.className = 'results-panel show error-panel';
    resultsPanel.innerHTML = `
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
        <span style="font-size:1.5rem;">✗</span>
        <strong style="font-size:1.1rem;">Validation Failed</strong>
      </div>
      <p style="color:var(--error);opacity:0.8;font-size:0.9rem;">
        Please fix the following fields: <strong>${invalidFields.join(', ')}</strong>
      </p>
    `;
  }

  // Scroll to results
  resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'center' });
}


// ─────────────────────────────────────────────
// §6  FILE UPLOAD UI HANDLER
// ─────────────────────────────────────────────

/**
 * Handle file selection from the drag-drop area
 */
function handleFileSelect(input) {
  if (input.files && input.files[0]) {
    const file = input.files[0];

    // Auto-populate fields from the selected file
    const nameField = document.getElementById('filename');
    const typeField = document.getElementById('filetype');
    const sizeField = document.getElementById('filesize');

    if (nameField && file.name) {
      nameField.value = file.name;
      validateFileName();
    }

    if (typeField && file.name) {
      typeField.value = file.name;
      validateFileType();
    }

    if (sizeField) {
      const sizeKB = file.size / 1024;
      if (sizeKB >= 1024) {
        sizeField.value = (sizeKB / 1024).toFixed(2) + ' MB';
      } else {
        sizeField.value = sizeKB.toFixed(2) + ' KB';
      }
      validateFileSize();
    }

    // Update upload area text
    const uploadText = document.querySelector('.upload-text');
    if (uploadText) {
      uploadText.textContent = 'Selected: ' + file.name;
    }
  }
}


// ─────────────────────────────────────────────
// §7  INITIALIZATION
// ─────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {
  // Attach real-time validation listeners
  const fields = {
    'username': validateUsername,
    'email': validateEmail,
    'filename': validateFileName,
    'filetype': validateFileType,
    'filesize': validateFileSize,
    'description': validateDescription
  };

  Object.entries(fields).forEach(([id, fn]) => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', fn);
      el.addEventListener('blur', fn);
    }
  });

  // Form submission
  const form = document.getElementById('upload-form');
  if (form) {
    form.addEventListener('submit', handleSubmit);
  }

  // Smooth scroll for nav links
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      // Update active state
      document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
      this.classList.add('active');
    });
  });

  // Intersection observer for nav active state
  const sections = document.querySelectorAll('.section[id]');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.id;
        document.querySelectorAll('.nav-link').forEach(l => {
          l.classList.toggle('active', l.getAttribute('href') === '#' + id);
        });
      }
    });
  }, { threshold: 0.3 });

  sections.forEach(s => observer.observe(s));

  // Submit button initially disabled
  updateSubmitButton();

  // Animate elements on scroll
  const animateObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('animate-in');
      }
    });
  }, { threshold: 0.1 });

  document.querySelectorAll('.regex-card, .dfa-container, .card').forEach(el => {
    animateObserver.observe(el);
  });
});
