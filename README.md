# C4 — Custom Cipher Challenges

A fully **offline**, edu-only classical-cipher engine with challenge generation,
real cryptanalysis auto-solvers, and provable planted-plaintext recovery.

## Overview

Implements five classical ciphers (Caesar, Vigenere, substitution, columnar
transposition, Enigma) and — for the first four — real automatic solvers that
recover the key and plaintext from ciphertext alone. `verify` proves the
solvers recover the exact planted plaintext every time.

## Features

- **Caesar**: encrypt/decrypt + brute-force solver (all 25 shifts scored by
  English frequency, bigrams, trigrams and dictionary word fit).
- **Vigenere**: encrypt/decrypt + automatic solver — Index-of-Coincidence key
  length candidates, per-column frequency key recovery, then coordinate-descent
  refinement over the 6 most plausible key lengths.
- **Substitution**: random-key monoalphabetic cipher with spaces preserved +
  word-pattern dictionary attack (pattern matching against a cipher vocabulary)
  with constraint-solving backtracking and a statistical fallback.
- **Transposition**: columnar transposition + solver that tries every key width
  and scores the result with English measures.
- **Enigma**: 3-rotor (I/II/III) + reflector B simulator with stepping; symmetric
  encrypt/decrypt. Manual decryption only (no key, no automated solve).

## Requirements

Python 3.7+, standard library only (argparse, json, unittest). No network, no
third-party dependencies. (The legacy `pip install pyenigma` line is no longer
needed.)

## Usage

```bash
# Generate a challenge (planted plaintext + ciphertext + key)
python3 cipher_challenges.py generate --cipher caesar --length 40
python3 cipher_challenges.py generate --cipher vigenere --length 300 --seed 7

# Encrypt your own text
python3 cipher_challenges.py encrypt --cipher caesar     --text "HELLO WORLD" --key 3
python3 cipher_challenges.py encrypt --cipher vigenere   --text ATTACKATDAWN --key LEMON
python3 cipher_challenges.py encrypt --cipher transposition --text THEQUICKFOX --key 4
python3 cipher_challenges.py encrypt --cipher substitution --key QWERTYUIOPASDFGHJKLZXCVBNM --text HELLO
python3 cipher_challenges.py encrypt --cipher enigma    --text "HELLO WORLD" --key "I:II:III"

# Auto-solve a ciphertext (recovers key + plaintext)
python3 cipher_challenges.py solve --cipher caesar        --text KHOORZRUOG
python3 cipher_challenges.py solve --cipher vigenere      --text "<ciphertext>"
python3 cipher_challenges.py solve --cipher substitution  --text "<ciphertext>"
python3 cipher_challenges.py solve --cipher transposition --text "<ciphertext>"

# Prove the solvers recover planted plaintexts exactly (exit 0 when all pass)
python3 cipher_challenges.py verify

# Offline demo (exit 0)
python3 cipher_challenges.py demo

# Machine-readable JSON for any command
python3 cipher_challenges.py generate --cipher caesar --json
python3 cipher_challenges.py solve --cipher caesar --text KHOORZRUOG --output reports/solve.json
```

## Solver notes

- Vigenere and substitution statistically need text of roughly 200+ characters
  of challenge vocabulary to guarantee exact recovery; the built-in `verify`
  and `demo` use length 250.
- Enigma is not auto-solvable without a key; it is provided as a simulator for
  studying rotor mechanics.

## Live Lab Test Plan

Run these in any Python 3 environment (no network, no filesystem requirements):

1. `python3 -m py_compile cipher_challenges.py` — syntax check, exit 0.
2. `python3 cipher_challenges.py demo` — runs all solvers on planted texts,
   prints `ALL PLANTED PLAINTEXTS RECOVERED`, exit 0.
3. `python3 cipher_challenges.py verify` — generates fresh challenges for all
   four solvable ciphers, asserts exact recovery, exit 0.
4. `python3 -m unittest discover -s tests` — unit + subprocess tests, all pass.
5. `python3 cipher_challenges.py generate --json` and `solve --json` — machine-
   readable JSON output path.

## Metrics

| Cipher        | Encrypt/Decrypt | Automated solve | Recovery method                  |
|---------------|-----------------|-----------------|----------------------------------|
| Caesar        | yes             | yes (exact)     | 25-shift brute force + scoring   |
| Vigenere      | yes             | yes (exact)     | IC key length + per-column + refinement |
| Substitution  | yes             | yes (exact)     | word-pattern dictionary + backtracking |
| Transposition | yes             | yes (exact)     | key-width search + scoring       |
| Enigma        | yes             | no              | simulator only, symmetric        |

Solvers recover the exact planted plaintext on every `verify`/`demo` run
(4/4 exact, character accuracy 1.0). Tests: 24 passing.

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the system owner before using this tool
- Cryptanalysis of systems you do not own or have authorization to test is illegal
- This tool should ONLY be used on systems you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Digital Millennium Copyright Act (DMCA)**: Circumvention of technological protection measures may be illegal
- **State Laws**: Many states have additional computer crime statutes
- **Export Controls**: Cryptographic tools may be subject to export regulations

### Acceptable Use
- Learning about classical cryptography
- CTF competitions and challenges
- Academic research and education
- Authorized penetration testing with written scope
- Historical cipher analysis

### Prohibited Use
- Attacking modern encryption systems
- Breaking encryption for unauthorized access
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT