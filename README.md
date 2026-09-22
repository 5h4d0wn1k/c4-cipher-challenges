> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# C4 — Cipher Challenges

A fully offline **cryptography** practice arena: five classical ciphers with
challenge generation, **real cryptanalysis auto-solvers**, scoring, and
provable planted-plaintext recovery for CTFs and security education.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/c4-cipher-challenges)](https://github.com/5h4d0wn1k/c4-cipher-challenges)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/c4-cipher-challenges)](https://github.com/5h4d0wn1k/c4-cipher-challenges)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/c4-cipher-challenges)](https://github.com/5h4d0wn1k/c4-cipher-challenges)

## Why C4

Classical ciphers are the gateway to modern cryptanalysis — but most tutorials
stop at encrypt/decrypt. C4 is a **CTF**-style arena where ciphers are drawn,
challenges are generated with planted plaintexts, and **automatic solvers**
break them from ciphertext alone: Caesar by scoring all 25 shifts, Vigenere by
Index-of-Coincidence key-length recovery, substitution by word-pattern
dictionary attack, and columnar transposition by key-width search. The
`verify` command proves the solvers recover the exact planted plaintext every
run. It is a **hacking education** tool for learning cryptanalysis on your own
data and challenges.

## Features

- **Five ciphers** — Caesar, Vigenere, substitution, columnar transposition, Enigma (3-rotor simulator)
- **Auto-solvers** — exact key+plaintext recovery for the first four ciphers
- **Challenge generator** — planted plaintext + ciphertext + key per cipher
- **Verification** — `verify` asserts exact plaintext recovery across solvers
- **Encrypt/decrypt CLI** — operate on your own text with any cipher
- **Scoring** — frequency, bigram, trigram, and dictionary word fit metrics
- **JSON output** — machine-readable results for tooling
- **Zero dependencies** — Python 3.7+ standard library only

## Quickstart

```bash
# Demo + verification
python3 cipher_challenges.py demo
python3 cipher_challenges.py verify

# Generate a challenge
python3 cipher_challenges.py generate --cipher caesar --length 40
python3 cipher_challenges.py generate --cipher vigenere --length 300 --seed 7

# Encrypt your own text
python3 cipher_challenges.py encrypt --cipher vigenere --text ATTACKATDAWN --key LEMON
python3 cipher_challenges.py encrypt --cipher enigma --text "HELLO WORLD" --key "I:II:III"

# Auto-solve a ciphertext
python3 cipher_challenges.py solve --cipher caesar --text KHOORZRUOG

# Tests
python3 -m unittest discover -s tests
```

> Note: Vigenere and substitution statistically need ~200+ characters of
> challenge vocabulary for exact recovery; `verify`/`demo` use length 250.
> Enigma is a simulator (symmetric encrypt/decrypt) — it has no automated solver.

## Project structure

- `cipher_challenges.py` — ciphers, solvers, generator, and CLI
- `tests/` — unit + subprocess tests over all five ciphers
- `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `ETHICS.md`, `SCOPE.md`, `SECURITY.md` — standards and legal scope

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT — see [LICENSE](LICENSE).

## Legal

- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md) · [SECURITY.md](SECURITY.md)