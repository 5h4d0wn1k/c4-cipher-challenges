# C4 — Custom Cipher Challenges

A collection of classical cipher implementations and solvers for cryptography challenges and education.

## Overview

This project implements various classical ciphers and cryptanalysis tools for learning about historical cryptography and cipher-breaking techniques.

## Features

- **Substitution Cipher**: Monoalphabetic substitution with frequency analysis
- **Transposition Cipher**: Columnar transposition with key-based rearrangement
- **Vigenere Cipher**: Polyalphabetic cipher with Kasiski examination
- **Caesar Cipher**: Simple shift cipher with brute force
- **Enigma Simulator**: WWII-era Enigma machine simulation

## Installation

```bash
pip install pyenigma
```

## Usage

```bash
# Caesar cipher
python3 cipher_challenges.py caesar --plaintext "HELLO" --shift 3

# Brute force Caesar
python3 cipher_challenges.py caesar --ciphertext "KHOOR" --brute-force

# Vigenere cipher
python3 cipher_challenges.py vigenere --plaintext "HELLO" --key "KEY"

# Kasiski analysis
python3 cipher_challenges.py vigenere --ciphertext "RIJVS..." --analyze

# Substitution cipher
python3 cipher_challenges.py substitution --plaintext "HELLO" --key "QWERTYUIOPASDFGHJKLZXCVBNM"

# Transposition cipher
python3 cipher_challenges.py transposition --plaintext "HELLO" --key 4

# Enigma simulator
python3 cipher_challenges.py enigma --rotors I,II,III --reflector B --plaintext "HELLO"

# Run all demonstrations
python3 cipher_challenges.py all
```

## Cipher Descriptions

### Caesar Cipher
Simple substitution cipher where each letter is shifted by a fixed number. Easily broken with brute force (25 possibilities) or frequency analysis.

### Vigenere Cipher
Polyalphabetic cipher using a keyword to shift each letter by different amounts. Broken using Kasiski examination to find key length, then frequency analysis.

### Substitution Cipher
Each letter is replaced with another letter based on a permutation. Broken using frequency analysis and known plaintext patterns.

### Transposition Cipher
Characters are rearranged based on a key. The original letters remain but are shuffled. Broken using anagram techniques and known plaintext.

### Enigma Machine
WWII-era electromechanical cipher machine with rotating wheels and reflectors. Each keypress changes the encryption path. Broken by Polish and British cryptanalysts.

## Example Output

```
=== C4 — Custom Cipher Challenges ===

[Caesar Cipher]
Plaintext:  HELLO
Ciphertext: KHOOR
Shift: 3

[Brute Force]
Shift 1: IFMMP
Shift 2: JGNNQ
Shift 3: KHOOR (key found!)
...

[Vigenere]
Plaintext:  ATTACKATDAWN
Key:         LEMON
Ciphertext: LXFOPVEFRNHR

[Kasiski Analysis]
Repeated segments found: 3
Probable key length: 4
Recovered key: KEY
```

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
