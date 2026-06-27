# Contributing to Secure File Upload Validation System

Thank you for your interest in contributing! This project is open to improvements, bug fixes, and new features.

---

## How to Contribute

### 1. Fork & Clone

```bash
git clone https://github.com/YOUR_USERNAME/regex.git
cd regex
```

### 2. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 3. Make Your Changes

- Keep changes focused and minimal
- Follow the existing code style
- Add comments for complex regex patterns
- Test your changes in multiple browsers

### 4. Commit with Descriptive Messages

Use conventional commits format:

```
feat: add MP4 file name validation pattern
fix: correct email TLD minimum length check
docs: update API validation patterns table
refactor: modularize validation functions
test: add edge cases for filename with spaces
```

### 5. Push & Open Pull Request

```bash
git push origin feature/your-feature-name
```

Then open a Pull Request on GitHub with:
- Clear title describing the change
- Description of what and why
- Link to any related issues

---

## What to Contribute

### Good First Issues
- Add support for new file extensions (`.mp3`, `.csv`, `.xlsx`)
- Improve error messages for better UX
- Add more test cases to documentation
- Fix typos in README or comments

### Feature Requests
- Advanced DFA/NFA visualizer
- Backend validation layer
- Jest unit test suite
- Internationalization (i18n) support

---

## Code Style Guidelines

- Use ES6+ JavaScript features
- Name regex patterns descriptively: `emailRegex`, `pdfFileRegex`
- Add JSDoc comments to functions
- Keep `validation.js` modular and well-documented

---

## Reporting Bugs

Open a GitHub Issue with:
- Browser and OS information
- Steps to reproduce
- Expected vs. actual behavior
- Screenshot if possible

---

## Code of Conduct

Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

---

Thank you for helping improve this project!
