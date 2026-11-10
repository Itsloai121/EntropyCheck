# 🟣 ZPC — Zynx Password Checker

A local-only password strength checker with two interfaces: a custom dark-purple desktop GUI and the original Rich terminal interface (TUI). ZPC evaluates password length, character variety, common-password words, simple patterns, a structural entropy estimate, and illustrative crack-time scenarios.

> **Use a test password, not a password you currently use.** ZPC is an educational checker. It is not a breach checker, password-cracking tool, or production security policy engine. Entropy and crack-time values are estimates, not guarantees.

## ✨ Features

- **GUI and TUI modes:** Choose the desktop GUI or terminal interface when the app starts. You can also launch either mode directly.
- **ZPC visual design:** Black-dominant background, purple secondary gradient, white accents, layered shadows, and floating controls.
- **Animated analysis screen:** A smooth progress animation with changing, fading status messages.
- **Organized report:** Score, grade, length, entropy, character pool, detected character categories, crack-time examples, findings, recommendations, and limitations.
- **Hidden password input:** Passwords are masked in the GUI and entered with `getpass` in the TUI.
- **Local processing:** No network requests, telemetry, or password-file storage.
- **Unicode-aware measurements:** Counts Python Unicode code points and labels its character-pool contribution as approximate.
- **Built-in tests:** Run deterministic checks for analysis and input-validation edge cases.

## 🧰 Requirements

- Python 3.10 or newer
- `rich` for the terminal interface
- Tkinter for the desktop GUI (usually included with Python; some minimal Linux installations package it separately)

The analysis logic and GUI use the Python standard library. `rich` is the only third-party Python dependency.

### Optional font

The GUI uses **Boldonse** for the large ZPC heading and primary button when that font is installed on your operating system. When it is not available, ZPC automatically uses a bold system font. Install Boldonse separately through your operating system's font manager to use the exact typeface.

Tkinter does not provide native cross-platform background blur. The GUI creates a soft glass-like appearance using dark gradients, layered panels, highlights, and shadows instead.

## 🚀 Installation

Open a terminal in the project folder and create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

**Windows PowerShell**

```powershell
.venv\Scripts\Activate.ps1
```

**Windows Command Prompt**

```bat
.venv\Scripts\activate.bat
```

**Linux / macOS**

```bash
source .venv/bin/activate
```

Install the requirements:

```bash
python -m pip install -r requirements.txt
```

## ▶️ Run ZPC

Start the interface chooser:

```bash
python zynx_password_checker.py
```

Open the GUI directly:

```bash
python zynx_password_checker.py --gui
```

Open the TUI directly in the current terminal:

```bash
python zynx_password_checker.py --tui
```

When you choose TUI from the Windows startup chooser, ZPC closes the chooser and opens a new PowerShell window for the terminal interface. On Linux and macOS, the TUI runs in the current terminal.

Other options:

```bash
python zynx_password_checker.py --self-test
python zynx_password_checker.py --version
python zynx_password_checker.py --help
```

## 🧠 How the analysis works

### 1. Password length and character categories

ZPC counts the exact characters entered, including spaces. It detects lowercase letters, uppercase letters, digits, symbols, and whitespace. It does not trim or rewrite the submitted value before measuring it.

### 2. Common-password and dictionary checks

A small built-in demonstration list checks for a few common passwords and dictionary words. The comparison uses Unicode normalization, case folding, and a limited set of predictable leetspeak substitutions. The original password is not changed, and ZPC reports only a generic finding rather than displaying the matched text.

The list is intentionally small. A clean result does **not** mean a password has never appeared in a data breach or is safe against every guessing strategy.

### 3. Obvious-pattern checks

ZPC looks for repeated runs of three or more characters, familiar keyboard rows such as `qwerty`, and simple four-character ascending or descending sequences such as `abcd` or `4321`. These are basic educational heuristics, not a complete pattern detector.

### 4. Structural entropy estimate

The application calculates:

```text
H = L × log₂(N)
```

Where:

- `H` is the estimated structural entropy in bits.
- `L` is the entered password length.
- `N` is the approximate character-pool size inferred from the character categories present.

For example, a 10-character value with an estimated pool of 62 characters gives:

```text
H = 10 × log₂(62)
H ≈ 59.54 bits
```

This is a theoretical upper-bound model. It assumes every character was chosen independently and uniformly from the entire estimated pool. Human-created passwords often do not meet that assumption. Non-ASCII character categories use a rough 100-character bucket, so Unicode estimates are especially approximate.

### 5. Crack-time scenarios

ZPC estimates median search time using:

```text
Expected guesses ≈ 2^(H - 1)
Estimated seconds = Expected guesses / guesses_per_second
```

The report compares two illustrative rates:

| Scenario | Assumed rate |
|---|---:|
| Online / rate-limited | 10 guesses per second |
| Offline / fast unsalted hash | 1,000,000,000 guesses per second |

Actual attack speeds depend on the target service, password-hashing algorithm and parameters, hardware, salts, and attack setup. The values shown are not predictions or guarantees.

### 6. Educational score

The 0–100 score is a transparent classroom heuristic. It awards points for length and character categories, then reduces the score for common-password matches and obvious patterns. It is not a recognized security standard and does not replace a password manager, unique passwords, multi-factor authentication, or secure password storage.

## 🛡️ Security and privacy

- Password input is masked in both interfaces.
- The password is analyzed locally; ZPC does not send it over the network.
- The password is not printed, written to a file, or included in the analysis report.
- The GUI clears its input field immediately after submission.
- Input is limited to 1,024 characters to keep the demonstration bounded.
- Python strings are immutable. Clearing a variable does not guarantee that the original bytes are immediately erased from process memory.

**Do not enter a real account password.** Use a temporary test value.

## 📁 Project structure

```text
EntropyCheck/
├── zynx_password_checker.py   # Analysis logic, GUI, TUI, and built-in tests
├── requirements.txt           # Rich terminal-interface dependency
├── README.md                  # Setup, usage, and methodology
├── bugs to fix.txt            # Original audit request/reference
└── design style.txt            # Original GUI design reference
```

ZPC intentionally keeps the application in one Python file. The GUI and TUI call the same analysis functions, so the two interfaces use the same scoring and detection logic.
