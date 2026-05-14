# Secure File Upload Validation System

A modern web-based validation system that demonstrates the use of **Regular Expressions (Regex)**, **DFA/NFA concepts**, and client-side validation techniques for secure file upload forms.

This project was developed as a **Theory of Computation (TOC)** mini project and focuses on validating user inputs such as file names and email addresses using regex-based pattern matching.

---

## 🚀 Live Demo

🌐 Project Link: [https://tushar-toc-regex.netlify.app/](https://tushar-toc-regex.netlify.app/)

📂 GitHub Repository: [https://github.com/tusharkkp/regex](https://github.com/tusharkkp/regex)

---

# 📌 Features

* ✅ File name validation using Regular Expressions
* ✅ Email address validation
* ✅ Interactive Regex Tester
* ✅ DFA/NFA state diagram representation
* ✅ Real-time validation feedback
* ✅ Fully responsive modern UI
* ✅ HTML + CSS + JavaScript implementation
* ✅ Theory explanation included
* ✅ Test cases and validation examples

---

# 🛠️ Tech Stack

## Frontend

* HTML5
* CSS3
* JavaScript (Vanilla JS)

## Concepts Used

* Regular Expressions (Regex)
* Deterministic Finite Automata (DFA)
* Non-Deterministic Finite Automata (NFA)
* Client-side Form Validation
* Pattern Matching

---

# 📂 Project Structure

```bash
202401040191_Topic_25/
│
├── index.html              # Main project file (HTML + CSS + JS)
├── validation.js           # Validation logic using Regex
├── Group_Report.pdf        # Project report
├── Test_Report.pdf         # Testing documentation
├── Theory_Supplement.pdf   # TOC theory explanation
├── Please_readme.md        # Basic project instructions
└── Please_readme.txt       # Additional notes
```

---

# ⚙️ How It Works

The system validates user inputs using predefined regex patterns.

### Example Validations

## 1. File Name Validation

Checks whether uploaded file names follow allowed naming conventions.

### Example Pattern

```regex
^[a-zA-Z0-9_-]+\.(jpg|png|pdf|docx)$
```

### Accepts

* report.pdf
* image.png
* notes.docx

### Rejects

* my file?.pdf
* [test@file.png](mailto:test@file.png)
* abc.exe

---

## 2. Email Validation

Ensures the entered email follows standard email formatting rules.

### Example Pattern

```regex
^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
```

### Accepts

* [user@gmail.com](mailto:user@gmail.com)
* [abc123@yahoo.in](mailto:abc123@yahoo.in)

### Rejects

* user@@gmail.com
* gmail.com
* user#mail.com

---

# 🧠 TOC Concepts Implemented

This project demonstrates practical implementation of:

* Regular Languages
* Finite Automata
* Regex-based lexical validation
* DFA/NFA transitions
* Pattern recognition systems

The included PDFs explain the theoretical background and state transitions used in the project.

---

# ▶️ How to Run the Project

## Method 1 — Directly Open HTML File

1. Download or clone the repository
2. Open `index.html` in any browser

---

## Method 2 — Using VS Code Live Server

1. Open project folder in VS Code
2. Install the **Live Server** extension
3. Right-click `index.html`
4. Click **Open with Live Server**

---

# 📸 Screens Included

The project interface contains:

* Secure File Upload Form
* Regex Testing Console
* DFA/NFA Visual Representation
* Validation Result Display
* Theory Explanation Section

---

# 🧪 Testing

The project includes:

* Positive test cases
* Negative test cases
* Validation reports
* Regex behavior testing
* Edge case checking

See:

* `Test_Report.pdf`
* `Group_Report.pdf`

---

# 🎯 Learning Outcomes

Through this project, the following concepts were understood practically:

* Designing Regex patterns
* Input validation techniques
* DFA/NFA modeling
* Secure form handling
* Frontend validation workflows
* Real-world application of TOC concepts

---

# 👨‍💻 Author

**Tushar Kaldate**

* GitHub: [https://github.com/tusharkkp](https://github.com/tusharkkp)
* Project: Secure File Upload Validation System

---


# ⭐ Acknowledgement

This project was developed as part of the **Theory of Computation (TOC)** coursework to demonstrate practical implementation of Regular Expressions and Finite Automata concepts in web-based validation systems.
