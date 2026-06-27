# Security Policy

## Supported Versions

This is a client-side static web application. No server-side components are involved.

| Version | Supported |
|---------|----------|
| Latest (main) | Yes |

## Reporting a Vulnerability

Although this is a frontend-only project, if you discover a security concern (e.g., a regex pattern that can cause ReDoS — Regular Expression Denial of Service), please:

1. **Do NOT open a public GitHub Issue** for security vulnerabilities.
2. Open a private GitHub security advisory via the **Security** tab of this repository.
3. Alternatively, contact the maintainer directly via GitHub: [@tusharkkp](https://github.com/tusharkkp)

## What Counts as a Security Issue

- **ReDoS (Regex Denial of Service):** A regex pattern that has catastrophic backtracking when given specially crafted input.
- **XSS via DOM manipulation:** If any future version processes unsanitized user input into the DOM.
- **Dependency vulnerabilities:** If dependencies are added in future, report any CVEs.

## Response Time

We aim to respond to security reports within **7 days** and provide a fix within **30 days** of confirmation.

## Security Best Practices Used

- All validation is regex-based with bounded quantifiers where possible
- No user data is sent to any server
- No third-party scripts or CDNs with known vulnerabilities are used
- Input is never directly injected into the DOM as HTML
