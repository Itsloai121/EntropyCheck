# 🔐 Password Lab — Password Strength Checker & Entropy Calculator

A local Python terminal application for learning how password length, character variety, common-password checks, and simple patterns affect a password-strength assessment.

> **Important:** This is an educational checker, not a password-cracking tool, a breach-database checker, or a production password policy engine. Its entropy and crack-time values are estimates, not guarantees.

## ✨ Features

- **Hidden password entry:** Uses Python's `getpass` so the password is not echoed on screen. The program deliberately refuses to fall back to visible password entry.
- **Length analysis:** Counts the exact characters entered, including spaces. Python counts Unicode code points.
- **Character-class detection:** Checks lowercase letters, uppercase letters, digits, symbols, and whitespace.
- **Common-password and dictionary checks:** Uses a small local demonstration list and a few predictable leetspeak substitutions.
- **Pattern checks:** Looks for repeated character runs, common keyboard rows, and simple ascending/descending sequences.
- **Structural entropy:** Calculates the upper-bound approximation `length × log₂(character_pool_size)`.
- **Crack-time scenarios:** Shows illustrative estimates for a rate-limited online scenario and a fast offline-hash scenario.
- **Recommendations:** Gives feedback based on length, dictionary matches, and detected patterns.
- **Built-in tests:** Includes deterministic unit tests that can be run from the command line.

## 🧰 Requirements

- Python 3.10 or newer
- `rich` for the terminal interface

The analysis logic uses Python's standard-library modules, including `re`, `math`, `string`, `getpass`, `unicodedata`, and `unittest`. `rich` is the only third-party dependency and is used for the visual TUI.

## 🚀 Installation

Open a terminal in the project folder and run:

```bash
python -m venv .venv
```

Activate the virtual environment:

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

Install the dependency:

```bash
python -m pip install -r requirements.txt
```

## ▶️ Run the application

```bash
python password_strength_checker.py
```

Choose `1` to analyze a test password. The input remains hidden while typing. Choose `Q` to exit.

Run the built-in tests:

```bash
python password_strength_checker.py --self-test
```

Display the version:

```bash
python password_strength_checker.py --version
```

## 🧠 How the analysis works

### 1. Password length

The program measures the length of the exact input. It does not trim spaces or silently modify the password. Longer passwords generally provide more resistance to guessing, especially when they are randomly generated or consist of several unrelated words.

### 2. Character categories

The checker detects these categories:

| Category | Examples |
|---|---|
| Lowercase | `a` to `z` |
| Uppercase | `A` to `Z` |
| Digits | `0` to `9` |
| Symbols | `!`, `@`, `#`, `$` |
| Whitespace | spaces and other whitespace characters |

For the alphabet-pool estimate, ASCII pools are counted separately when present: 26 lowercase letters, 26 uppercase letters, 10 digits, and the characters in Python's `string.punctuation`. Whitespace adds one modeled choice. Non-ASCII categories use a rough 100-character bucket, so Unicode results are especially approximate.

Character variety is displayed because it is part of this project's learning objective. It should not be treated as a requirement to mechanically add one uppercase letter, one digit, and one symbol. Length, uniqueness, blocklists, and unpredictability matter more than satisfying a predictable recipe.

### 3. Common-password and dictionary detection

The tool compares a normalized form of the input with a small built-in list. It also extracts alphabetic tokens to identify common words in values such as a common word followed by digits. A few substitutions such as `0 → o`, `3 → e`, and `@ → a` are normalized for this check.

The original password is not changed. The match result is generic; the application never prints the password or the matched text. The bundled list is intentionally small and does not contain real-time breach data, so a clean result does **not** prove that a password has never been exposed or is not guessable.

### 4. Obvious-pattern detection

The checker looks for:

- A character repeated three or more times in a row.
- Familiar keyboard rows such as `qwerty` or `asdf`.
- Four-character ascending or descending sequences such as `abcd` or `4321`.

These checks are deliberately simple educational heuristics. They do not cover every human password pattern.

### 5. Structural entropy calculation

The program uses this formula:

```text
H = L × log₂(N)
```

Where:

- `H` = estimated structural entropy in bits.
- `L` = password length.
- `N` = estimated number of possible characters in the alphabet pool detected in the password.

For example, if a password has 10 characters and the detected pool contains 62 possible characters:

```text
H = 10 × log₂(62)
H ≈ 59.54 bits
```

This is a **theoretical upper-bound model**. It assumes each character was selected independently and uniformly at random from the entire detected pool. A human-created password usually does not satisfy that assumption. A phrase, name, date, keyboard walk, or predictable substitution can be much easier to guess than the formula suggests. The program therefore shows dictionary and pattern warnings separately instead of pretending that one entropy number captures every attack strategy.

### 6. Crack-time estimation

The checker estimates the median search time using:

```text
Expected guesses ≈ 2^(H - 1)
Estimated seconds = Expected guesses / guesses_per_second
```

It displays two configurable scenarios from constants near the top of the Python file:

| Scenario | Default rate | Meaning |
|---|---:|---|
| Online / rate-limited | 10 guesses per second | A simplified online-guessing illustration. Real services should rate-limit attempts and may be much slower. |
| Offline / fast unsalted hash | 1,000,000,000 guesses per second | A deliberately fast illustration for a weak/fast hash, not a prediction for a modern password hash. |

Real offline attack speed depends heavily on the hashing algorithm and its parameters, the attacker's hardware, and the attack setup. Proper password storage uses a unique salt and a deliberately expensive password-hashing scheme. The displayed time is not a promise that a password will survive for that long.

### 7. Educational strength score

The 0–100 score is a transparent classroom heuristic:

- Most points come from password length.
- A smaller number of points come from detected character categories.
- Common-password/dictionary matches force the score down.
- Obvious patterns remove points.

The score is not a recognized security standard and is not a substitute for a password blocklist, a password manager, multi-factor authentication, rate limiting, or secure password storage.

## 🛡️ Security and privacy choices

- The password is entered through `getpass` and is not echoed to the terminal.
- If hidden input is unavailable, the program exits rather than switching to visible input.
- The application does not send data over the network.
- The password is not written to a file, printed, or included in the report object.
- The report stores only derived measurements and findings.
- The app has a 1,024-character demonstration limit to avoid unbounded input processing.

**Python memory limitation:** Deleting the local variable after analysis does not guarantee that the original string is immediately erased from process memory. Python strings are immutable and cannot be reliably zeroed by this program. Therefore, use a test password rather than a real password for an important account.

## 📁 Project files

```text
password_strength_checker/
├── password_strength_checker.py
├── README.md
└── requirements.txt
```

## 📚 Standards note

NIST SP 800-63B-4 (July 2025) emphasizes password length and blocklists of commonly used, expected, or compromised passwords. It specifies a 15-character minimum for passwords used as a single authentication factor, permits a lower minimum in some MFA contexts, and advises against additional composition rules such as requiring a mix of character types. This project displays character variety for educational entropy calculations, but it does not present composition rules as a current best-practice requirement.

Official reference: [NIST SP 800-63B-4 — Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)

---

**Project purpose:** Demonstrate password hygiene concepts, basic Python modules, regular expressions, information-theory-style calculations, terminal UI design, and defensive security awareness.
