#!/usr/bin/env python3
"""Tests for C4 - Cipher Challenges."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cipher_challenges import (
    CaesarCipher, VigenereCipher, SubstitutionCipher, TranspositionCipher,
    EnigmaCipher, ChallengeGenerator, clean, run_verification,
)


class TestCaesarCipher(unittest.TestCase):
    def test_encrypt_known(self):
        self.assertEqual(CaesarCipher.encrypt('HELLO', 3), 'KHOOR')

    def test_decrypt_known(self):
        self.assertEqual(CaesarCipher.decrypt('KHOOR', 3), 'HELLO')

    def test_roundtrip(self):
        for shift in range(1, 26):
            ct = CaesarCipher.encrypt('THE QUICK BROWN FOX', shift)
            self.assertEqual(CaesarCipher.decrypt(ct, shift), 'THEQUICKBROWNFOX')

    def test_solve_recovers(self):
        ct = CaesarCipher.encrypt('ATTACK AT DAWN', 7)
        solved = CaesarCipher.solve(ct)
        self.assertEqual(solved['plaintext'], 'ATTACKATDAWN')
        self.assertEqual(solved['key'], 7)

    def test_solve_all_24_ciphers(self):
        for shift in range(1, 25):
            pt = 'THIS IS A SECRET MESSAGE NUMBER'
            ct = CaesarCipher.encrypt(pt, shift)
            solved = CaesarCipher.solve(ct)
            self.assertEqual(solved['plaintext'], pt.replace(' ', ''), f'shift={shift}')


class TestVigenereCipher(unittest.TestCase):
    def test_encrypt_known(self):
        self.assertEqual(VigenereCipher.encrypt('ATTACKATDAWN', 'LEMON'), 'LXFOPVEFRNHR')

    def test_decrypt_known(self):
        self.assertEqual(VigenereCipher.decrypt('LXFOPVEFRNHR', 'LEMON'), 'ATTACKATDAWN')

    def test_roundtrip(self):
        ct = VigenereCipher.encrypt('THE WOLF BITES AT DAWN', 'KEY')
        self.assertEqual(VigenereCipher.decrypt(ct, 'KEY'), 'THEWOLFBITESATDAWN')

    def test_solve_recovers_long_text(self):
        text = ('THE EMPIRE OF KNOWLEDGE NEVER SETS ON THE SUN OF CRYPTOGRAPHY '
                'EVERY CODE HAS A KEY THAT LOCKS THE SECRETS IN PLAIN SIGHT '
                'WHEN CRYPTOGRAPHY IS THE ART OF HIDING SECRETS WE MUST TRUST')
        ct = VigenereCipher.encrypt(text, 'SUN')
        solved = VigenereCipher().solve(ct)
        self.assertEqual(solved['plaintext'], text.replace(' ', ''))
        self.assertEqual(solved['key'], 'SUN')

    def test_solve_key_length_detection(self):
        text = ('THE EMPIRE OF KNOWLEDGE NEVER SETS ON THE SUN OF CRYPTOGRAPHY '
                'EVERY CODE HAS A KEY THAT LOCKS THE SECRETS IN PLAIN SIGHT '
                'WHEN CRYPTOGRAPHY IS THE ART OF HIDING SECRETS WE MUST TRUST')
        ct = VigenereCipher.encrypt(text, 'KEY')
        solved = VigenereCipher().solve(ct)
        self.assertEqual(solved['key_length'], 3)
        self.assertEqual(solved['key'], 'KEY')


class TestSubstitutionCipher(unittest.TestCase):
    def test_roundtrip(self):
        import random
        random.seed(5)
        sub = SubstitutionCipher()
        ct = sub.encrypt('THE WOLF BITES AT DAWN')
        self.assertEqual(sub.decrypt(ct), 'THE WOLF BITES AT DAWN')

    def test_word_pattern(self):
        self.assertEqual(SubstitutionCipher.word_pattern('HELLO'), 'ABCCD')

    def test_pattern_matches(self):
        self.assertTrue(SubstitutionCipher.pattern_matches('ABCCD', 'HELLO'))
        self.assertFalse(SubstitutionCipher.pattern_matches('ABCDE', 'HELLO'))

    def test_solve_recovers_exact(self):
        import random
        random.seed(7)
        gen = ChallengeGenerator()
        pt = gen.random_plaintext(200)
        sub = SubstitutionCipher()
        ct = sub.encrypt(pt)
        solved = sub.solve(ct)
        self.assertEqual(solved['plaintext'], pt)

    def test_solve_multiple_keys(self):
        import random
        for seed in range(3):
            random.seed(seed)
            gen = ChallengeGenerator()
            pt = gen.random_plaintext(150)
            sub = SubstitutionCipher()
            ct = sub.encrypt(pt)
            solved = sub.solve(ct)
            self.assertEqual(solved['plaintext'], pt, f'seed={seed}')


class TestTranspositionCipher(unittest.TestCase):
    def test_roundtrip(self):
        for key in range(2, 9):
            ct = TranspositionCipher.encrypt('THE QUICK BROWN FOX JUMPS', key)
            self.assertEqual(TranspositionCipher.decrypt(ct, key), 'THEQUICKBROWNFOXJUMPS',
                             f'key={key}')

    def test_solve_recovers(self):
        import random
        random.seed(11)
        gen = ChallengeGenerator()
        pt = gen.random_plaintext(200)
        key = 5
        ct = TranspositionCipher.encrypt(pt, key)
        solved = TranspositionCipher.solve(ct, max_key=12)
        self.assertEqual(solved['key'], key)
        self.assertEqual(solved['plaintext'], pt.replace(' ', ''))


class TestEnigmaCipher(unittest.TestCase):
    def test_roundtrip(self):
        en = EnigmaCipher(['I', 'II', 'III'], 'B', [0, 0, 0])
        ct = en.encrypt('HELLO WORLD')
        en2 = EnigmaCipher(['I', 'II', 'III'], 'B', [0, 0, 0])
        self.assertEqual(en2.encrypt(ct), 'HELLOWORLD')

    def test_polyalphabetic_property(self):
        en = EnigmaCipher(['I', 'II', 'III'], 'B', [0, 0, 0])
        ct = en.encrypt('AAAAAAAAAA')
        self.assertEqual(len(set(ct)), 10, 'Enigma output should not repeat for same input')

    def test_key_rotation(self):
        en1 = EnigmaCipher(['I', 'II', 'III'], 'B', [5, 5, 5])
        en2 = EnigmaCipher(['I', 'II', 'III'], 'B', [0, 0, 0])
        c1 = en1.encrypt('TESTING')
        c2 = en2.encrypt('TESTING')
        self.assertNotEqual(c1, c2)


class TestChallengeGenerator(unittest.TestCase):
    def test_generate_all_ciphers(self):
        gen = ChallengeGenerator()
        for cipher in gen.CIPHERS:
            ch = gen.generate(cipher, 100)
            self.assertIn('ciphertext', ch)
            self.assertGreater(len(ch['ciphertext']), 0)

    def test_verify_all_solvable(self):
        results = run_verification(seed=99, length=250)
        for r in results:
            self.assertTrue(r['exact_recovery'], f"cipher failed: {r['cipher']}")
            self.assertAlmostEqual(r['character_accuracy'], 1.0)


class TestDemoMode(unittest.TestCase):
    def test_demo_exits_clean(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), 'cipher_challenges.py'), 'demo'],
            capture_output=True, text=True, timeout=60
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn('ALL PLANTED PLAINTEXTS RECOVERED', result.stdout)

    def test_verify_command(self):
        import subprocess
        result = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), 'cipher_challenges.py'), 'verify'],
            capture_output=True, text=True, timeout=60
        )
        self.assertEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()