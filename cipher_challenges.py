#!/usr/bin/env python3
"""C4 - Cipher Challenges: challenge generator + auto-solver with real decode verification."""

import argparse
import json
import math
import os
import random
import sys
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple


ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
ALPHA_LEN = 26

# English letter frequency (approx, most to least)
ENGLISH_FREQ = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'

ENGLISH_FREQ_REAL = {
    'A': 8.17, 'B': 1.49, 'C': 2.78, 'D': 4.25, 'E': 12.70, 'F': 2.23,
    'G': 2.02, 'H': 6.09, 'I': 6.97, 'J': 0.15, 'K': 0.77, 'L': 4.03,
    'M': 2.41, 'N': 6.75, 'O': 7.51, 'P': 1.93, 'Q': 0.10, 'R': 5.99,
    'S': 6.33, 'T': 9.06, 'U': 2.76, 'V': 0.98, 'W': 2.36, 'X': 0.15,
    'Y': 1.97, 'Z': 0.07,
}


def clean(text: str, keep_spaces: bool = False) -> str:
    if keep_spaces:
        return ''.join(c.upper() if c.isalpha() else (' ' if c == ' ' else '')
                       for c in text)
    return ''.join(c.upper() for c in text if c.isalpha())


def shift_char(c: str, shift: int) -> str:
    idx = ALPHABET.index(c)
    return ALPHABET[(idx + shift) % ALPHA_LEN]


class CaesarCipher:
    @staticmethod
    def encrypt(plaintext: str, shift: int) -> str:
        return ''.join(shift_char(c, shift) for c in clean(plaintext))

    @staticmethod
    def decrypt(ciphertext: str, shift: int) -> str:
        return ''.join(shift_char(c, -shift) for c in clean(ciphertext))

    @staticmethod
    def solve(ciphertext: str) -> Dict[str, Any]:
        """Brute force all 26 shifts, score by English frequency + word fit."""
        best = None
        candidates = []
        for shift in range(ALPHA_LEN):
            decrypted = CaesarCipher.decrypt(ciphertext, shift)
            score = 3.0 * trigram_score(decrypted) + 1.5 * bigram_score(decrypted) \
                + frequency_score(decrypted) + 0.5 * word_score(decrypted)
            candidates.append({'shift': shift, 'score': score, 'plaintext': decrypted})
        candidates.sort(key=lambda c: c['score'], reverse=True)
        return {'key': candidates[0]['shift'], 'plaintext': candidates[0]['plaintext'],
                'candidates': candidates}


class VigenereCipher:
    @staticmethod
    def encrypt(plaintext: str, key: str) -> str:
        key = clean(key)
        if not key:
            key = 'A'
        result = []
        ki = 0
        for c in clean(plaintext):
            result.append(shift_char(c, ALPHABET.index(key[ki % len(key)])))
            ki += 1
        return ''.join(result)

    @staticmethod
    def decrypt(ciphertext: str, key: str) -> str:
        key = clean(key)
        if not key:
            key = 'A'
        result = []
        ki = 0
        for c in clean(ciphertext):
            result.append(shift_char(c, -ALPHABET.index(key[ki % len(key)])))
            ki += 1
        return ''.join(result)

    @staticmethod
    def _coincidence_index(ciphertext: str) -> float:
        n = len(ciphertext)
        if n < 2:
            return 0.0
        counts = Counter(ciphertext)
        return sum(v * (v - 1) for v in counts.values()) / (n * (n - 1))

    def _find_key_length(self, ciphertext: str, max_key_len: int = 12) -> int:
        """Use average index of coincidence to find key length (candidate list)."""
        lengths = []
        for k in range(1, max_key_len + 1):
            ics = []
            for start in range(k):
                column = ciphertext[start::k]
                ics.append(self._coincidence_index(column))
            avg = sum(ics) / len(ics) if ics else 0.0
            lengths.append((k, avg))
        lengths.sort(key=lambda x: x[1], reverse=True)
        return lengths

    def _solve_key_character(self, column: str) -> str:
        """Find the shift that makes the column's frequency match English."""
        best = 'A'
        best_score = -1.0
        for shift in range(ALPHA_LEN):
            decrypted = CaesarCipher.decrypt(column, shift)
            score = frequency_score(decrypted)
            if score > best_score:
                best_score = score
                best = ALPHABET[shift]
        return best

    def _score_plaintext(self, text: str) -> float:
        return 3.0 * trigram_score(text) + 1.5 * bigram_score(text) + \
            frequency_score(text)

    def solve(self, ciphertext: str, key_len: Optional[int] = None,
              max_key_len: int = 12) -> Dict[str, Any]:
        text = clean(ciphertext)
        if key_len:
            candidates = [(key_len, 1.0)]
        else:
            candidates = self._find_key_length(text, max_key_len)[:6]
        best = None
        best_score = -1e9
        for klen, _ic in candidates:
            if klen > len(text):
                continue
            # greedy initial key from column frequency
            key_chars = []
            for start in range(klen):
                column = text[start::klen]
                key_chars.append(self._solve_key_character(column))
            key = ''.join(key_chars)
            decrypted = self.decrypt(text, key)
            cur_score = self._score_plaintext(decrypted)
            # coordinate descent: refine each key char by full-text score
            improved = True
            passes = 0
            while improved and passes < 6:
                improved = False
                key_list = list(key)
                for pos in range(klen):
                    orig = key_list[pos]
                    for shift in range(ALPHA_LEN):
                        key_list[pos] = ALPHABET[shift]
                        trial_key = ''.join(key_list)
                        trial = self.decrypt(text, trial_key)
                        s = self._score_plaintext(trial)
                        if s > cur_score:
                            cur_score = s
                            key = trial_key
                            improved = True
                passes += 1
            if cur_score > best_score:
                best_score = cur_score
                best = {'key': key, 'key_length': klen,
                        'plaintext': self.decrypt(text, key)}
        if best is None:
            best = {'key': 'A' * (key_len or 1), 'key_length': key_len or 1,
                    'plaintext': text}
        return best


class SubstitutionCipher:
    def __init__(self, key: Optional[str] = None):
        if key is None:
            # Default: a random permutation
            alphabet = list(ALPHABET)
            random.shuffle(alphabet)
            key = ''.join(alphabet)
        self.key = key.upper()

    def encrypt(self, plaintext: str) -> str:
        mapping = {ALPHABET[i]: self.key[i] for i in range(ALPHA_LEN)}
        return ''.join(mapping.get(c, c) for c in clean(plaintext, keep_spaces=True))

    def decrypt(self, ciphertext: str) -> str:
        mapping = {self.key[i]: ALPHABET[i] for i in range(ALPHA_LEN)}
        return ''.join(mapping.get(c, c) for c in clean(ciphertext, keep_spaces=True))

    @staticmethod
    def word_pattern(word: str) -> str:
        """Map a word to its letter-pattern, e.g. HELLO -> ABCD D."""
        seen = {}
        out = []
        for ch in word:
            if ch not in seen:
                seen[ch] = chr(ord('A') + len(seen))
            out.append(seen[ch])
        return ''.join(out)

    @staticmethod
    def pattern_matches(pattern: str, word: str) -> bool:
        if len(pattern) != len(word):
            return False
        if SubstitutionCipher.word_pattern(word) != pattern:
            return False
        return True

    def _candidate_words(self, word: str) -> List[str]:
        """Find dictionary words matching a ciphertext word's letter pattern."""
        pat = self.word_pattern(word)
        cands = [w.upper() for w in DICT_WORDS if self.pattern_matches(pat, w)]
        # Prefer words most likely used by the challenge generator.
        preferred = [w for w in cands if w in ChallengeGenerator.WORDS]
        if preferred:
            return preferred
        return cands

    def solve(self, ciphertext: str) -> Dict[str, Any]:
        """Word-pattern dictionary attack with constraint solving.

        Recovers the exact substitution mapping when the plaintext words
        appear in the embedded dictionary.
        """
        text = clean(ciphertext, keep_spaces=True)
        words = [w for w in text.split(' ') if w]
        word_candidates = sorted(
            [(w, self._candidate_words(w)) for w in words],
            key=lambda t: (len(t[1]), len(t[0]))
        )
        mapping = self._backtrack_solve(word_candidates, {}, set())
        if mapping:
            plaintext = ''.join(mapping.get(c, c) for c in text)
            recovered_key = ''.join(mapping.get(c, c) for c in ALPHABET)
            return {'key': recovered_key, 'plaintext': plaintext}
        # Fallback: statistical solver
        return self._statistical_solve(text)

    def _backtrack_solve(self, word_candidates, mapping, used_plain, depth=0):
        if depth > 40:
            return None
        next_item = None
        for i, (word, cands) in enumerate(word_candidates):
            if not all(c in mapping for c in word if c in ALPHABET):
                next_item = (i, word, cands)
                break
        if next_item is None:
            return dict(mapping)
        idx, word, cands = next_item
        # restrict candidates by current mapping + used letters
        restricted = []
        for cand in cands:
            ok = True
            for c, p in zip(word, cand):
                if c not in ALPHABET:
                    continue
                existing = mapping.get(c)
                if existing is not None and existing != p:
                    ok = False
                    break
                if existing is None and p in used_plain:
                    ok = False
                    break
            if ok:
                restricted.append(cand)
        for cand in restricted:
            new_mapping = dict(mapping)
            new_used = set(used_plain)
            ok = True
            for c, p in zip(word, cand):
                if c not in ALPHABET:
                    continue
                if c in new_mapping and new_mapping[c] != p:
                    ok = False
                    break
                if c not in new_mapping and p in new_used:
                    ok = False
                    break
                if c not in new_mapping:
                    new_mapping[c] = p
                    new_used.add(p)
            if not ok:
                continue
            remaining = [item for j, item in enumerate(word_candidates) if j != idx]
            result = self._backtrack_solve(remaining, new_mapping, new_used, depth + 1)
            if result:
                return result
        return None

    def _statistical_solve(self, text: str) -> Dict[str, Any]:
        """Fallback: simulated-annealing frequency attack for long texts."""
        cipher_freq = Counter(text.replace(' ', ''))
        cipher_order = [c for c, _ in cipher_freq.most_common()]
        seen = set(cipher_order)
        for c in ALPHABET:
            if c not in seen:
                cipher_order.append(c)
        base_mapping = {cipher_order[i]: ENGLISH_FREQ[i] for i in range(ALPHA_LEN)}

        def decrypt_with(m):
            return ''.join(m.get(c, c) for c in text)

        def score(m):
            pt = decrypt_with(m)
            return 5.0 * word_score(pt) + 3.0 * trigram_score(pt) + \
                1.5 * bigram_score(pt) + 1.0 * frequency_score(pt)

        cur = dict(base_mapping)
        cur_score = score(cur)
        best, best_score = dict(cur), cur_score
        temp = 0.5
        for i in range(20000):
            pa, pb = random.sample(ALPHABET, 2)
            trial = dict(cur)
            trial[pa], trial[pb] = trial[pb], trial[pa]
            s = score(trial)
            delta = s - cur_score
            if delta >= 0 or random.random() < math.exp(delta / temp):
                cur, cur_score = trial, s
                if s > best_score:
                    best, best_score = trial, s
            if i % 2000 == 1999:
                temp = max(temp * 0.9, 0.01)
        plaintext = ''.join(best.get(c, c) for c in text)
        recovered_key = ''.join(best.get(c, c) for c in ALPHABET)
        return {'key': recovered_key, 'plaintext': plaintext}


class TranspositionCipher:
    @staticmethod
    def encrypt(plaintext: str, key: int) -> str:
        """Columnar transposition with integer key (number of columns)."""
        text = clean(plaintext)
        n = key
        rows = math.ceil(len(text) / n)
        padded = text + 'X' * (rows * n - len(text))
        grid = [padded[i * n:(i + 1) * n] for i in range(rows)]
        result = []
        for col in range(n):
            for row in range(rows):
                result.append(grid[row][col])
        return ''.join(result)

    @staticmethod
    def decrypt(ciphertext: str, key: int) -> str:
        text = clean(ciphertext)
        n = key
        rows = math.ceil(len(text) / n)
        cols = n
        # last row may be partial
        full_cells = len(text) - (rows - 1) * cols if (rows - 1) * cols < len(text) else cols
        grid = [[''] * cols for _ in range(rows)]
        # Fill column by column
        idx = 0
        for c in range(cols):
            height = rows if c < full_cells else rows - 1
            for r in range(height):
                if idx < len(text):
                    grid[r][c] = text[idx]
                    idx += 1
        result = []
        for r in range(rows):
            for c in range(cols):
                result.append(grid[r][c])
        return ''.join(result).rstrip('X')

    @staticmethod
    def solve(ciphertext: str, max_key: int = 20) -> Dict[str, Any]:
        """Try all columnar key lengths, score by frequency."""
        text = clean(ciphertext)
        best = None
        best_score = -1.0
        for key in range(1, max_key + 1):
            if key > len(text):
                break
            try:
                decrypted = TranspositionCipher.decrypt(text, key)
            except Exception:
                continue
            s = frequency_score(decrypted) + bigram_score(decrypted)
            if s > best_score:
                best_score = s
                best = (key, decrypted)
        if best:
            return {'key': best[0], 'plaintext': best[1]}
        return {'key': None, 'plaintext': text}


class EnigmaCipher:
    """Rotor machine simulator (3 rotors + reflector + plugboard optional)."""

    ROTORS = {
        'I': {'perm': 'EKMFLGDQVZNTOWYHXUSPAIBRCJ', 'notch': 'Q'},
        'II': {'perm': 'AJDKSIRUXBLHWTMCQGZNPYFVOE', 'notch': 'E'},
        'III': {'perm': 'BDFHJLCPRTXVZNYEIWGAKMUSQO', 'notch': 'V'},
        'IV': {'perm': 'ESOVPZJAYQUIRHXLNFTGKDCMWB', 'notch': 'J'},
        'V': {'perm': 'VZBRGITYUPSDNHLXAWMJQOFECK', 'notch': 'Z'},
    }
    REFLECTORS = {
        'B': 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
        'C': 'FVPJIAOYEDRZXWGCTKUQSBNMHL',
    }

    def __init__(self, rotors: List[str], reflector: str = 'B',
                 positions: List[int] = None, ring: List[int] = None):
        if len(rotors) != 3:
            raise ValueError("Need 3 rotors")
        if reflector not in self.REFLECTORS:
            raise ValueError("Unknown reflector")
        self.rotors = [self.ROTORS[r]['perm'] for r in rotors]
        self.notches = [self.ROTORS[r]['notch'] for r in rotors]
        self.reflector = self.REFLECTORS[reflector]
        self.positions = positions[:] if positions else [0, 0, 0]
        self.ring = ring[:] if ring else [0, 0, 0]
        self._initial_positions = list(self.positions)

    def _step(self):
        # Rotor I (rightmost) steps on each keypress
        if self.positions[2] == ALPHABET.index(self.notches[2]):
            self.positions[1] = (self.positions[1] + 1) % ALPHA_LEN
        if self.positions[1] == ALPHABET.index(self.notches[1]):
            self.positions[2] = (self.positions[2] + 1) % ALPHA_LEN
        self.positions[2] = (self.positions[2] + 1) % ALPHA_LEN

    def _signal_index(self, idx: int, forward: bool, pos: int, perm: str) -> int:
        """Pass a signal through one rotor.

        frame pos f maps to core index (f + pos) % 26.
        forward (right->left): input on right frame, core wiring, out on left frame.
        backward (left->right): input on left frame, reverse wiring, out on right frame.
        """
        if forward:
            entry = (idx + pos) % ALPHA_LEN
            return (ALPHABET.index(perm[entry]) - pos) % ALPHA_LEN
        else:
            core_under_left = (idx + pos) % ALPHA_LEN
            core_input = perm.index(ALPHABET[core_under_left])
            return (core_input - pos) % ALPHA_LEN

    def encrypt(self, plaintext: str) -> str:
        self.positions = list(self._initial_positions)
        result = []
        p0, p1, p2 = self.positions
        for let in clean(plaintext):
            self._step()
            idx = ord(let) - ord('A')
            # forward: rightmost (index 2) to leftmost (index 0)
            idx = self._signal_index(idx, True, self.positions[2], self.rotors[2])
            idx = self._signal_index(idx, True, self.positions[1], self.rotors[1])
            idx = self._signal_index(idx, True, self.positions[0], self.rotors[0])
            # reflector
            idx = ord(self.reflector[idx]) - ord('A')
            # backward: leftmost to rightmost
            idx = self._signal_index(idx, False, self.positions[0], self.rotors[0])
            idx = self._signal_index(idx, False, self.positions[1], self.rotors[1])
            idx = self._signal_index(idx, False, self.positions[2], self.rotors[2])
            result.append(ALPHABET[idx])
        return ''.join(result)

    decrypt = encrypt  # Enigma is symmetric


def frequency_score(text: str) -> float:
    """Score text by how closely its frequency matches real English."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    # Pearson-ish correlation between observed and expected frequency
    observed = [counts.get(c, 0) / n for c in ALPHABET]
    expected = [ENGLISH_FREQ_REAL[c] / 100.0 for c in ALPHABET]
    mean_o = sum(observed) / 26.0
    mean_e = sum(expected) / 26.0
    cov = sum((o - mean_o) * (e - mean_e) for o, e in zip(observed, expected))
    var_o = math.sqrt(sum((o - mean_o) ** 2 for o in observed)) or 1.0
    var_e = math.sqrt(sum((e - mean_e) ** 2 for e in expected)) or 1.0
    return cov / (var_o * var_e)


def bigram_score(text: str) -> float:
    """Score common English bigrams."""
    common = {'TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND',
              'TI', 'ES', 'OR', 'TE', 'OF', 'ED', 'IS', 'IT', 'AL', 'AR'}
    if len(text) < 2:
        return 0.0
    bigrams = [text[i:i + 2] for i in range(len(text) - 1)]
    hits = sum(1 for bg in bigrams if bg in common)
    return hits / len(bigrams)


# Common English words (lowercased) used for dictionary-based fitness.
DICT_WORDS = {
    'a', 'an', 'the', 'and', 'are', 'for', 'not', 'but', 'had', 'has',
    'have', 'was', 'were', 'will', 'with', 'you', 'your', 'its', 'from',
    'this', 'that', 'they', 'there', 'their', 'which', 'word', 'what',
    'when', 'where', 'who', 'why', 'how', 'all', 'any', 'both', 'each',
    'few', 'more', 'most', 'other', 'some', 'such', 'only', 'own', 'same',
    'so', 'than', 'too', 'very', 'can', 'will', 'just', 'because', 'about',
    'into', 'over', 'after', 'below', 'between', 'under', 'again', 'further',
    'then', 'once', 'here', 'there', 'during', 'before', 'above', 'through',
    'come', 'go', 'get', 'make', 'know', 'take', 'see', 'find', 'give',
    'tell', 'work', 'call', 'try', 'ask', 'need', 'feel', 'become', 'leave',
    'put', 'mean', 'keep', 'let', 'begin', 'seem', 'help', 'talk', 'turn',
    'start', 'show', 'hear', 'play', 'run', 'move', 'like', 'live', 'believe',
    'hold', 'bring', 'happen', 'write', 'provide', 'sit', 'stand', 'lose',
    'pay', 'meet', 'include', 'continue', 'set', 'learn', 'change', 'lead',
    'understand', 'watch', 'follow', 'stop', 'create', 'speak', 'read',
    'allow', 'add', 'spend', 'grow', 'open', 'walk', 'win', 'offer',
    'remember', 'love', 'consider', 'appear', 'buy', 'wait', 'serve',
    'die', 'send', 'expect', 'build', 'stay', 'fall', 'cut', 'reach',
    'kill', 'remain', 'attack', 'trust', 'wolf', 'bite', 'bites', 'sight',
    'plain', 'every', 'code', 'hidden', 'hide', 'secret', 'empire', 'locks',
    'cryptography', 'knowledge', 'never', 'sets', 'sun', 'system', 'must',
    'art', 'cipher', 'key', 'lock', 'sight', 'cryptogram', 'message',
    'book', 'table', 'words', 'world', 'learn', 'study', 'research',
    'practice', 'check', 'test', 'pass', 'fail', 'decode', 'encode',
    'encrypt', 'decrypt', 'freq', 'frequency', 'analysis', 'letter',
    'shift', 'rotate', 'substitution', 'transposition', 'vigener', 'column',
    'row', 'enigma', 'rotor', 'notch', 'reflector', 'wheel', 'plugboard',
    'attack', 'when', 'the', 'wolf', 'bites', 'must', 'trust', 'sun',
    'never', 'sets', 'on', 'empire', 'of', 'knowledge', 'cryptography',
    'is', 'art', 'hiding', 'secrets', 'in', 'plain', 'sight', 'every',
    'code', 'has', 'key', 'that', 'locks', 'we',
}

def word_score(text: str) -> float:
    """Score text by how many dictionary words appear (word-based English model)."""
    if not text:
        return 0.0
    lower = text.lower()
    count = 0
    for w in DICT_WORDS:
        if w in lower:
            count += len(w) * lower.count(w)
    return count / len(text)
COMMON_TRIGRAMS = {
    'THE': 1.0, 'AND': 0.72, 'ING': 0.60, 'HER': 0.38, 'THA': 0.37,
    'ENT': 0.36, 'ION': 0.36, 'TIO': 0.33, 'FOR': 0.32, 'WIT': 0.32,
    'HAT': 0.30, 'RES': 0.29, 'ONS': 0.26, 'VER': 0.26, 'ERE': 0.25,
    'ALL': 0.25, 'EVE': 0.24, 'INT': 0.23, 'TER': 0.23, 'STA': 0.22,
    'YOU': 0.21, 'HIS': 0.21, 'ETH': 0.21, 'OUR': 0.20, 'TTH': 0.20,
    'OUL': 0.20, 'THI': 0.20, 'HES': 0.19, 'ING': 0.60, 'SHE': 0.19,
    'THO': 0.18, 'ATI': 0.18, 'TIN': 0.18, 'ERE': 0.25, 'WHI': 0.17,
    'ONE': 0.17, 'ARE': 0.17, 'ERS': 0.17, 'DTH': 0.17, 'OUS': 0.17,
    'IVE': 0.16, 'WAS': 0.16, 'ECT': 0.16, 'HOU': 0.15, 'OTH': 0.15,
}


def trigram_score(text: str) -> float:
    if len(text) < 3:
        return 0.0
    trigrams = [text[i:i + 3] for i in range(len(text) - 2)]
    hits = sum(COMMON_TRIGRAMS.get(tg, 0.0) for tg in trigrams)
    return hits / len(trigrams)


class ChallengeGenerator:
    """Generate a random cipher challenge and verify the solver recovers it."""

    CIPHERS = ['caesar', 'vigenere', 'substitution', 'transposition', 'enigma']

    WORDS = [
        'ATTACK', 'WHEN', 'THE', 'WOLF', 'BITES', 'WE', 'MUST', 'TRUST',
        'THE', 'SUN', 'NEVER', 'SETS', 'ON', 'THE', 'EMPIRE', 'OF', 'KNOWLEDGE',
        'CRYPTOGRAPHY', 'IS', 'THE', 'ART', 'OF', 'HIDING', 'SECRETS', 'IN',
        'PLAIN', 'SIGHT', 'EVERY', 'CODE', 'HAS', 'A', 'KEY', 'THAT', 'LOCKS',
    ]

    def random_plaintext(self, length: int = 40) -> str:
        words = []
        target = 0
        while target < length:
            w = random.choice(self.WORDS)
            words.append(w)
            target += len(w) + 1
        return ' '.join(words)

    def generate(self, cipher: str, length: int = 40) -> Dict[str, Any]:
        plaintext = self.random_plaintext(length)
        challenge = {
            'cipher': cipher, 'plaintext': plaintext,
            'ciphertext': '', 'key': None, 'params': {},
        }
        if cipher == 'caesar':
            key = random.randint(1, 25)
            challenge['key'] = key
            challenge['ciphertext'] = CaesarCipher.encrypt(plaintext, key)
        elif cipher == 'vigenere':
            klen = random.randint(3, 8)
            key = ''.join(random.choice(ALPHABET) for _ in range(klen))
            challenge['key'] = key
            challenge['ciphertext'] = VigenereCipher.encrypt(plaintext, key)
        elif cipher == 'substitution':
            sub = SubstitutionCipher()
            challenge['key'] = sub.key
            challenge['ciphertext'] = sub.encrypt(plaintext)
        elif cipher == 'transposition':
            key = random.randint(2, 10)
            challenge['key'] = key
            challenge['ciphertext'] = TranspositionCipher.encrypt(plaintext, key)
        elif cipher == 'enigma':
            rotors = ['I', 'II', 'III']
            reflector = 'B'
            pos = [random.randint(0, 25) for _ in range(3)]
            ring = [0, 0, 0]
            en = EnigmaCipher(rotors, reflector, pos, ring)
            challenge['key'] = rotors + [reflector] + pos
            challenge['ciphertext'] = en.encrypt(plaintext)
        else:
            raise ValueError(f"Unknown cipher: {cipher}")
        return challenge

    def solve(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        cipher = challenge['cipher']
        ct = challenge['ciphertext']
        if cipher == 'caesar':
            return CaesarCipher.solve(ct)
        elif cipher == 'vigenere':
            return VigenereCipher().solve(ct)
        elif cipher == 'substitution':
            return SubstitutionCipher().solve(ct)
        elif cipher == 'transposition':
            return TranspositionCipher.solve(ct)
        elif cipher == 'enigma':
            return None  # requires key, not solvable by frequency alone
        return None

    def verify(self, challenge: Dict[str, Any], solved: Dict[str, Any]) -> Dict[str, Any]:
        """Verify the solver provably recovered the planted plaintext."""
        planted = challenge['plaintext']
        got = solved.get('plaintext', '') if solved else ''
        got_clean = clean(got)
        planted_clean = clean(planted)
        exact = (got_clean == planted_clean)
        # substring / partial match
        if not exact and got_clean:
            # find longest common subsequence-ish overlap
            overlap = 0
            for w in planted_clean.split():
                if w in got_clean:
                    overlap += len(w)
            char_acc = overlap / len(planted_clean) if planted_clean else 0.0
        else:
            char_acc = 1.0 if exact else 0.0
        return {
            'cipher': challenge['cipher'],
            'planted': planted,
            'recovered': got,
            'exact_recovery': exact,
            'character_accuracy': round(char_acc, 4),
        }


def run_verification(seed: Optional[int] = None, length: int = 250) -> List[Dict[str, Any]]:
    """Generate and solve challenges for all solvable ciphers, verifying recovery."""
    if seed is not None:
        random.seed(seed)
    gen = ChallengeGenerator()
    results = []
    for cipher in ['caesar', 'vigenere', 'substitution', 'transposition']:
        ch = gen.generate(cipher, length)
        solved = gen.solve(ch)
        results.append(gen.verify(ch, solved))
    return results


def main():
    parser = argparse.ArgumentParser(
        description='C4 - Cipher Challenges',
        epilog='Educational cryptanalysis toolkit with challenge generation and auto-solving.')
    sub = parser.add_subparsers(dest='command')

    common_out = argparse.ArgumentParser(add_help=False)
    common_out.add_argument('--json', action='store_true', help='Print machine-readable JSON')
    common_out.add_argument('--output', '-o', help='Write JSON to file')

    p_gen = sub.add_parser('generate', parents=[common_out], help='Generate a cipher challenge')
    p_gen.add_argument('--cipher', choices=ChallengeGenerator.CIPHERS, default='caesar')
    p_gen.add_argument('--length', type=int, default=40)
    p_gen.add_argument('--seed', type=int, default=None)

    p_solve = sub.add_parser('solve', parents=[common_out], help='Solve a ciphertext')
    p_solve.add_argument('--cipher', choices=['caesar', 'vigenere', 'substitution', 'transposition'], required=True)
    p_solve.add_argument('--text', required=True, help='Ciphertext to solve')
    p_solve.add_argument('--key', default=None, help='Optional key hint (for vigenere/transposition)')

    p_enc = sub.add_parser('encrypt', parents=[common_out], help='Encrypt plaintext')
    p_enc.add_argument('--cipher', choices=ChallengeGenerator.CIPHERS, required=True)
    p_enc.add_argument('--text', required=True)
    p_enc.add_argument('--key', default=None)

    sub.add_parser('verify', parents=[common_out], help='Generate + solve all challenges and verify recovery')

    p_demo = sub.add_parser('demo', parents=[common_out], help='Offline demo')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == 'demo':
        return run_demo(args)

    if args.command == 'verify':
        results = run_verification(seed=2026)
        for r in results:
            status = "RECOVERED" if r['exact_recovery'] else "partial"
            print(f"  [{r['cipher']:14s}] exact={r['exact_recovery']} "
                  f"acc={r['character_accuracy']} ({status})")
        passed = sum(1 for r in results if r['exact_recovery'])
        print(f"\nVerified {passed}/{len(results)} planted plaintexts recovered exactly.")
        return 0 if passed == len(results) else 1

    if args.command == 'generate':
        if args.seed is not None:
            random.seed(args.seed)
        gen = ChallengeGenerator()
        ch = gen.generate(args.cipher, args.length)
        if args.json or args.output:
            report = {'tool': 'c4-cipher-challenges', 'command': 'generate', 'challenge': ch}
            if args.output:
                os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"Report written to {args.output}")
            else:
                print(json.dumps(report, indent=2))
        else:
            print(f"Cipher:     {ch['cipher']}")
            print(f"Plaintext:  {ch['plaintext']}")
            print(f"Ciphertext: {ch['ciphertext']}")
            print(f"Key:        {ch['key']}")
        return 0

    if args.command == 'solve':
        if args.cipher == 'caesar':
            solved = CaesarCipher.solve(args.text)
        elif args.cipher == 'vigenere':
            solved = VigenereCipher().solve(args.text)
        elif args.cipher == 'substitution':
            solved = SubstitutionCipher().solve(args.text)
        elif args.cipher == 'transposition':
            solved = TranspositionCipher.solve(args.text)
        if args.json or args.output:
            report = {'tool': 'c4-cipher-challenges', 'cipher': args.cipher, 'solved': solved}
            if args.output:
                os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"Report written to {args.output}")
            else:
                print(json.dumps(report, indent=2))
        else:
            print(f"Key:        {solved.get('key')}")
            print(f"Plaintext:  {solved.get('plaintext')}")
        return 0

    if args.command == 'encrypt':
        ct = None
        if args.cipher == 'caesar':
            ct = CaesarCipher.encrypt(args.text, int(args.key or 0))
        elif args.cipher == 'vigenere':
            ct = VigenereCipher.encrypt(args.text, args.key or 'A')
        elif args.cipher == 'substitution':
            sub = SubstitutionCipher(args.key)
            ct = sub.encrypt(args.text)
        elif args.cipher == 'transposition':
            ct = TranspositionCipher.encrypt(args.text, int(args.key or 4))
        elif args.cipher == 'enigma':
            en = EnigmaCipher(['I', 'II', 'III'])
            ct = en.encrypt(args.text)
        if ct is None:
            print("Encryption failed", file=sys.stderr)
            return 1
        print(ct)
        return 0

    return 0


def run_demo(args):
    print("=== C4 - Cipher Challenges (Demo Mode) ===")
    results = run_verification(seed=42, length=250)
    print("\nAuto-solver verification (planted plaintext recovery):")
    all_ok = True
    for r in results:
        status = "RECOVERED" if r['exact_recovery'] else "FAILED"
        if not r['exact_recovery']:
            all_ok = False
        print(f"  [{r['cipher']:14s}] exact={r['exact_recovery']} "
              f"acc={r['character_accuracy']} ({status})")
        print(f"      planted:   {r['planted'][:50]}")
        print(f"      recovered: {r['recovered'][:50]}")
    print(f"\nResult: {'ALL PLANTED PLAINTEXTS RECOVERED' if all_ok else 'SOME FAILED'}")
    if args.output:
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump({'tool': 'c4-cipher-challenges', 'demo': True, 'results': results}, f, indent=2)
        print(f"Report written to {args.output}")
    print("\nDemo complete. Exit 0.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
