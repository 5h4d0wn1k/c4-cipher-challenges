#!/usr/bin/env python3
"""
C4 — Custom Cipher Challenges
Classical cipher implementations for cryptography education.
"""

import argparse
import string
import sys
from typing import Optional, List, Tuple
from collections import Counter

# === Caesar Cipher ===

def caesar_encrypt(plaintext: str, shift: int) -> str:
    """Encrypt using Caesar cipher."""
    result = []
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            encrypted = (ord(char) - base + shift) % 26 + base
            result.append(chr(encrypted))
        else:
            result.append(char)
    return ''.join(result)

def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt using Caesar cipher."""
    return caesar_encrypt(ciphertext, -shift)

def caesar_brute_force(ciphertext: str) -> List[Tuple[int, str]]:
    """Brute force all 25 possible shifts."""
    results = []
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        results.append((shift, decrypted))
    return results

def demo_caesar(plaintext: str = "HELLO WORLD", shift: int = 3):
    """Demonstrate Caesar cipher."""
    print("\n[Caesar Cipher]")
    print(f"Plaintext:  {plaintext}")
    
    ciphertext = caesar_encrypt(plaintext, shift)
    print(f"Ciphertext: {ciphertext}")
    print(f"Shift:      {shift}")
    
    decrypted = caesar_decrypt(ciphertext, shift)
    print(f"Decrypted:  {decrypted}")
    
    print("\n[Brute Force]")
    results = caesar_brute_force(ciphertext)
    for s, text in results[:5]:  # Show first 5
        print(f"Shift {s:2d}: {text}")
    print("...")


# === Vigenere Cipher ===

def vigenere_encrypt(plaintext: str, key: str) -> str:
    """Encrypt using Vigenere cipher."""
    result = []
    key_idx = 0
    key = key.upper()
    
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')
            encrypted = (ord(char) - base + shift) % 26 + base
            result.append(chr(encrypted))
            key_idx += 1
        else:
            result.append(char)
    
    return ''.join(result)

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt using Vigenere cipher."""
    result = []
    key_idx = 0
    key = key.upper()
    
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            shift = ord(key[key_idx % len(key)]) - ord('A')
            decrypted = (ord(char) - base - shift) % 26 + base
            result.append(chr(decrypted))
            key_idx += 1
        else:
            result.append(char)
    
    return ''.join(result)

def find_repeated_sequences(text: str, min_length: int = 3) -> List[Tuple[str, List[int]]]:
    """Find repeated sequences in ciphertext for Kasiski analysis."""
    sequences = {}
    for i in range(len(text) - min_length + 1):
        seq = text[i:i+min_length]
        if seq.isalpha():
            if seq not in sequences:
                sequences[seq] = []
            sequences[seq].append(i)
    
    return [(seq, positions) for seq, positions in sequences.items() if len(positions) > 1]

def find_key_length(ciphertext: str) -> int:
    """Estimate key length using Kasiski examination."""
    sequences = find_repeated_sequences(ciphertext)
    
    if not sequences:
        return 1
    
    # Calculate GCD of distances between repeated sequences
    distances = []
    for seq, positions in sequences:
        for i in range(1, len(positions)):
            distances.append(positions[i] - positions[i-1])
    
    if not distances:
        return 1
    
    # Find most common divisor
    from math import gcd
    from functools import reduce
    
    common_divisors = Counter()
    for d in distances:
        for i in range(2, min(d, 20)):
            if d % i == 0:
                common_divisors[i] += 1
    
    if common_divisors:
        return common_divisors.most_common(1)[0][0]
    return 1

def kasiski_attack(ciphertext: str) -> Tuple[str, str]:
    """
    Attempt to break Vigenere using frequency analysis.
    Returns (estimated_key, decrypted_text).
    """
    key_length = find_key_length(ciphertext.upper())
    alpha_only = ''.join(c for c in ciphertext.upper() if c.isalpha())
    
    key = []
    for i in range(key_length):
        # Extract i-th letter of each group
        group = alpha_only[i::key_length]
        
        # Find shift using frequency analysis
        freq = Counter(group)
        most_common = freq.most_common(1)[0][0]
        # 'E' is most common letter in English
        shift = (ord(most_common) - ord('E')) % 26
        key.append(chr(shift + ord('A')))
    
    key_str = ''.join(key)
    decrypted = vigenere_decrypt(ciphertext, key_str)
    return key_str, decrypted

def demo_vigenere(plaintext: str = "ATTACKATDAWN", key: str = "LEMON"):
    """Demonstrate Vigenere cipher."""
    print("\n[Vigenere Cipher]")
    print(f"Plaintext:  {plaintext}")
    
    ciphertext = vigenere_encrypt(plaintext, key)
    print(f"Ciphertext: {ciphertext}")
    print(f"Key:        {key}")
    
    decrypted = vigenere_decrypt(ciphertext, key)
    print(f"Decrypted:  {decrypted}")
    
    print("\n[Kasiski Analysis]")
    test_text = vigenere_encrypt("THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG " * 5, "SECRET")
    print(f"Ciphertext: {test_text[:50]}...")
    recovered_key, recovered_text = kasiski_attack(test_text)
    print(f"Recovered key: {recovered_key}")
    print(f"Recovered text: {recovered_text[:50]}...")


# === Substitution Cipher ===

def generate_substitution_key(seed: int = 42) -> str:
    """Generate a random substitution key."""
    import random
    random.seed(seed)
    alphabet = list(string.ascii_uppercase)
    shuffled = alphabet.copy()
    random.shuffle(shuffled)
    return ''.join(shuffled)

def substitution_encrypt(plaintext: str, key: str) -> str:
    """Encrypt using substitution cipher."""
    result = []
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            idx = ord(char.upper()) - ord('A')
            encrypted = key[idx]
            if char.islower():
                encrypted = encrypted.lower()
            result.append(encrypted)
        else:
            result.append(char)
    return ''.join(result)

def substitution_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt using substitution cipher."""
    result = []
    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            idx = key.index(char.upper())
            decrypted = chr(idx + ord('A'))
            if char.islower():
                decrypted = decrypted.lower()
            result.append(decrypted)
        else:
            result.append(char)
    return ''.join(result)

def frequency_analysis(ciphertext: str) -> List[Tuple[str, float]]:
    """Perform frequency analysis on ciphertext."""
    alpha_only = ''.join(c for c in ciphertext.upper() if c.isalpha())
    total = len(alpha_only)
    if total == 0:
        return []
    
    freq = Counter(alpha_only)
    return [(char, count/total) for char, count in freq.most_common()]

def demo_substitution(plaintext: str = "HELLO WORLD"):
    """Demonstrate substitution cipher."""
    print("\n[Substitution Cipher]")
    
    key = generate_substitution_key()
    print(f"Key: {key}")
    print(f"Plaintext:  {plaintext}")
    
    ciphertext = substitution_encrypt(plaintext, key)
    print(f"Ciphertext: {ciphertext}")
    
    decrypted = substitution_decrypt(ciphertext, key)
    print(f"Decrypted:  {decrypted}")
    
    print("\n[Frequency Analysis]")
    freq = frequency_analysis(ciphertext)
    print("Letter frequencies in ciphertext:")
    for char, f in freq[:10]:
        print(f"  {char}: {f:.2%}")


# === Transposition Cipher ===

def transposition_encrypt(plaintext: str, key: int) -> str:
    """Encrypt using columnar transposition cipher."""
    # Remove spaces and uppercase
    text = plaintext.replace(" ", "").upper()
    
    # Calculate number of rows
    num_rows = (len(text) + key - 1) // key
    
    # Fill grid
    grid = [['' for _ in range(key)] for _ in range(num_rows)]
    idx = 0
    for r in range(num_rows):
        for c in range(key):
            if idx < len(text):
                grid[r][c] = text[idx]
                idx += 1
    
    # Read off columns in key order
    result = []
    for c in range(key):
        for r in range(num_rows):
            if grid[r][c]:
                result.append(grid[r][c])
    
    return ''.join(result)

def transposition_decrypt(ciphertext: str, key: int) -> str:
    """Decrypt using columnar transposition cipher."""
    text = ciphertext.replace(" ", "").upper()
    
    num_rows = (len(text) + key - 1) // key
    num_full_cols = len(text) % key if len(text) % key != 0 else key
    num_empty = key - num_full_cols if num_full_cols < key else 0
    
    # Calculate column lengths
    col_lengths = [num_rows] * key
    for i in range(num_empty):
        col_lengths[key - 1 - i] = num_rows - 1
    
    # Fill columns
    idx = 0
    grid = [['' for _ in range(key)] for _ in range(num_rows)]
    for c in range(key):
        for r in range(col_lengths[c]):
            if idx < len(text):
                grid[r][c] = text[idx]
                idx += 1
    
    # Read off rows
    result = []
    for r in range(num_rows):
        for c in range(key):
            if grid[r][c]:
                result.append(grid[r][c])
    
    return ''.join(result)

def demo_transposition(plaintext: str = "HELLO WORLD", key: int = 4):
    """Demonstrate transposition cipher."""
    print("\n[Transposition Cipher]")
    print(f"Plaintext:  {plaintext}")
    
    ciphertext = transposition_encrypt(plaintext, key)
    print(f"Ciphertext: {ciphertext}")
    print(f"Key (columns): {key}")
    
    decrypted = transposition_decrypt(ciphertext, key)
    print(f"Decrypted:  {decrypted}")


# === Enigma Simulator ===

class EnigmaRotor:
    """Simulates an Enigma rotor."""
    
    def __init__(self, wiring: str, notches: List[int], position: int = 0):
        self.wiring = wiring.upper()
        self.notches = notches
        self.position = position
        self.ring_setting = 0
    
    def forward(self, c: int) -> int:
        """Forward pass through rotor."""
        shifted = (c + self.position - self.ring_setting) % 26
        wired = ord(self.wiring[shifted]) - ord('A')
        return (wired - self.position + self.ring_setting) % 26
    
    def backward(self, c: int) -> int:
        """Backward pass through rotor."""
        shifted = (c + self.position - self.ring_setting) % 26
        wired = self.wiring.index(chr(shifted + ord('A')))
        return (wired - self.position + self.ring_setting) % 26
    
    def step(self) -> bool:
        """Step the rotor, return True if it triggers double step."""
        notch_hit = self.position in self.notches
        self.position = (self.position + 1) % 26
        return notch_hit

class EnigmaReflector:
    """Simulates an Enigma reflector."""
    
    def __init__(self, wiring: str):
        self.wiring = wiring.upper()
    
    def reflect(self, c: int) -> int:
        return ord(self.wiring[c]) - ord('A')

class EnigmaMachine:
    """Simulates an Enigma machine."""
    
    # Standard rotor wirings
    ROTORS = {
        'I': ('EKMFLGDQVZNTOWYHXUSPAIBRCJ', [4]),
        'II': ('AJDKSIRUXBLHWTMCQGZNPYFVOE', [3]),
        'III': ('BDFHJLCPRTXVZNYEIWGAKMUSQO', [5]),
        'IV': ('ESOVPZJAYQUIRHXLNFTGKDCMWB', [6]),
        'V': ('VZBRGITYUPSDNHLXAWMJQOFECK', [7]),
    }
    
    REFLECTORS = {
        'B': ('YRUHQSLDPXNGOKMIEBFZCWVJAT'),
        'C': ('FVPJIAOYEDRZXWGCTKUQSBNMHL'),
    }
    
    def __init__(self, rotors: List[str], reflector: str, 
                 positions: List[int] = None, ring_settings: List[int] = None):
        self.rotors = []
        for i, rotor_name in enumerate(rotors):
            wiring, notches = self.ROTORS[rotor_name]
            position = positions[i] if positions else 0
            ring = ring_settings[i] if ring_settings else 0
            rotor = EnigmaRotor(wiring, notches, position)
            rotor.ring_setting = ring
            self.rotors.append(rotor)
        
        self.reflector = EnigmaReflector(self.REFLECTORS[reflector])
        self.plugboard = {}
    
    def set_plugboard(self, pairs: str):
        """Set plugboard connections (e.g., "AB CD EF")."""
        self.plugboard = {}
        for pair in pairs.split():
            if len(pair) == 2:
                a, b = pair.upper()
                self.plugboard[ord(a) - ord('A')] = ord(b) - ord('A')
                self.plugboard[ord(b) - ord('A')] = ord(a) - ord('A')
    
    def step_rotors(self):
        """Step rotors with double-stepping mechanism."""
        # Middle rotor at notch steps left rotor
        if len(self.rotors) > 1 and self.rotors[1].position in self.rotors[1].notches:
            self.rotors[0].step()
        
        # Right rotor always steps
        self.rotors[-1].step()
    
    def encrypt_char(self, c: str) -> str:
        """Encrypt a single character."""
        if not c.isalpha():
            return c
        
        x = ord(c.upper()) - ord('A')
        
        # Plugboard in
        if x in self.plugboard:
            x = self.plugboard[x]
        
        # Rotors forward
        for rotor in reversed(self.rotors):
            x = rotor.forward(x)
        
        # Reflector
        x = self.reflector.reflect(x)
        
        # Rotors backward
        for rotor in self.rotors:
            x = rotor.backward(x)
        
        # Plugboard out
        if x in self.plugboard:
            x = self.plugboard[x]
        
        result = chr(x + ord('A'))
        return result if c.isupper() else result.lower()
    
    def encrypt(self, text: str) -> str:
        """Encrypt/decrypt text."""
        result = []
        for c in text:
            if c.isalpha():
                self.step_rotors()
            result.append(self.encrypt_char(c))
        return ''.join(result)

def demo_enigma(plaintext: str = "HELLO"):
    """Demonstrate Enigma machine."""
    print("\n[Enigma Simulator]")
    
    # Create Enigma machine (M3 configuration)
    enigma = EnigmaMachine(['I', 'II', 'III'], 'B', [0, 0, 0])
    enigma.set_plugboard("AB CD EF")
    
    print(f"Plaintext:  {plaintext}")
    
    # Encrypt
    ciphertext = enigma.encrypt(plaintext)
    print(f"Ciphertext: {ciphertext}")
    
    # Reset and decrypt
    enigma = EnigmaMachine(['I', 'II', 'III'], 'B', [0, 0, 0])
    enigma.set_plugboard("AB CD EF")
    
    decrypted = enigma.encrypt(ciphertext)
    print(f"Decrypted:  {decrypted}")
    
    print("\n[Enigma with different settings]")
    enigma2 = EnigmaMachine(['IV', 'V', 'I'], 'C', [5, 10, 15])
    enigma2.set_plugboard("GK IA JM")
    
    ciphertext2 = enigma2.encrypt(plaintext)
    print(f"Ciphertext: {ciphertext2}")
    
    enigma2 = EnigmaMachine(['IV', 'V', 'I'], 'C', [5, 10, 15])
    enigma2.set_plugboard("GK IA JM")
    decrypted2 = enigma2.encrypt(ciphertext2)
    print(f"Decrypted:  {decrypted2}")


# === Main CLI ===

def main():
    parser = argparse.ArgumentParser(
        description="C4 — Custom Cipher Challenges",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ciphers:
  caesar          Caesar cipher (shift cipher)
  vigenere        Vigenere cipher
  substitution    Monoalphabetic substitution cipher
  transposition   Columnar transposition cipher
  enigma          Enigma machine simulator
  all             Run all demonstrations
        """
    )
    
    parser.add_argument("cipher",
                       choices=["caesar", "vigenere", "substitution", "transposition", "enigma", "all"],
                       help="Cipher to demonstrate")
    
    parser.add_argument("--plaintext", type=str, default="HELLO WORLD",
                       help="Plaintext to encrypt")
    
    parser.add_argument("--key", type=str, default=None,
                       help="Cipher key")
    
    parser.add_argument("--shift", type=int, default=3,
                       help="Caesar cipher shift (default: 3)")
    
    parser.add_argument("--columns", type=int, default=4,
                       help="Transposition cipher columns (default: 4)")
    
    parser.add_argument("--brute-force", action="store_true",
                       help="Brute force Caesar cipher")
    
    parser.add_argument("--analyze", action="store_true",
                       help="Perform Kasiski analysis on ciphertext")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("C4 — Custom Cipher Challenges")
    print("=" * 60)
    
    if args.cipher == "caesar":
        if args.brute_force:
            print("\n[Caesar Brute Force]")
            ciphertext = args.key if args.key else caesar_encrypt(args.plaintext, args.shift)
            results = caesar_brute_force(ciphertext)
            for shift, text in results:
                print(f"Shift {shift:2d}: {text}")
        else:
            demo_caesar(args.plaintext, args.shift)
    
    elif args.cipher == "vigenere":
        key = args.key if args.key else "KEY"
        if args.analyze:
            ciphertext = args.plaintext  # Treat input as ciphertext
            recovered_key, recovered_text = kasiski_attack(ciphertext)
            print(f"\n[Kasiski Attack]")
            print(f"Ciphertext: {ciphertext}")
            print(f"Recovered key: {recovered_key}")
            print(f"Recovered text: {recovered_text}")
        else:
            demo_vigenere(args.plaintext, key)
    
    elif args.cipher == "substitution":
        demo_substitution(args.plaintext)
    
    elif args.cipher == "transposition":
        demo_transposition(args.plaintext, args.columns)
    
    elif args.cipher == "enigma":
        demo_enigma(args.plaintext)
    
    elif args.cipher == "all":
        demo_caesar(args.plaintext, args.shift)
        demo_vigenere(args.plaintext, "KEY")
        demo_substitution(args.plaintext)
        demo_transposition(args.plaintext, args.columns)
        demo_enigma(args.plaintext)
    
    print("\n" + "=" * 60)
    print("Demonstration complete!")
    print("=" * 60)

if __name__ == "__main__":
    main()
