"""
Password Cracking Demonstration & Benchmarking Script
-----------------------------------------------------
This script accompanies the assignment to demonstrate:
1. Proof of Salting: Two identical passwords producing distinct hashes.
2. Speed Comparison: Fast hashing (SHA-256) vs Slow Key-Stretching (Bcrypt Cost 12).
3. Dictionary Attack Simulation: Demonstrating how fast SHA-256 is cracked vs Bcrypt.
4. SQL Injection Resistance test: Demonstrating parameterized query protection.
"""

import time
import hashlib
import bcrypt
import sqlite3
import os
import db

def demo_salting():
    print("=" * 65)
    print("DEMO 1: PROOF OF SALTING (Identical Passwords -> Distinct Hashes)")
    print("=" * 65)
    password = "SecurePassword@2026"
    
    # Hash the same password twice using bcrypt
    hash1 = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    hash2 = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
    
    print(f"Password: '{password}'")
    print(f"User 1 Hash (salt embedded): {hash1}")
    print(f"User 2 Hash (salt embedded): {hash2}")
    print(f"Are hashes identical? {hash1 == hash2}")
    print("Conclusion: Salting ensures identical passwords have completely different")
    print("hashes, rendering precomputed Rainbow Tables useless!\n")


def demo_cracking_speed_benchmark():
    print("=" * 65)
    print("DEMO 2: CRACKING BENCHMARK (SHA-256 vs Bcrypt Cost 12)")
    print("=" * 65)
    
    target_password = "password123"
    wordlist = [
        "123456", "admin", "welcome", "qwerty", "letmein",
        "monkey", "dragon", "football", "baseball", "password123"
    ]
    
    # --- 1. SHA-256 Test ---
    sha256_target = hashlib.sha256(target_password.encode("utf-8")).hexdigest()
    print(f"Target SHA-256 Digest: {sha256_target}")
    
    start_sha = time.perf_counter()
    sha_cracked = None
    sha_guesses = 0
    for word in wordlist:
        sha_guesses += 1
        guess_hash = hashlib.sha256(word.encode("utf-8")).hexdigest()
        if guess_hash == sha256_target:
            sha_cracked = word
            break
    sha_time = time.perf_counter() - start_sha
    
    print(f"[SHA-256] Cracked password: '{sha_cracked}' in {sha_guesses} attempts")
    print(f"[SHA-256] Total time: {sha_time * 1000:.4f} ms (avg {sha_time / sha_guesses * 1000:.5f} ms per attempt)")
    print(f"[SHA-256] Estimated speed: ~{int(sha_guesses / max(sha_time, 1e-9)):,} hashes/second on single CPU core")
    print("-" * 65)

    # --- 2. Bcrypt Test ---
    salt = bcrypt.gensalt(rounds=12)
    bcrypt_target = bcrypt.hashpw(target_password.encode("utf-8"), salt)
    print(f"Target Bcrypt Hash: {bcrypt_target.decode('utf-8')}")
    print("Attempting dictionary attack against Bcrypt (Cost 12)...")
    
    start_bcrypt = time.perf_counter()
    bcrypt_cracked = None
    bcrypt_guesses = 0
    for word in wordlist:
        bcrypt_guesses += 1
        if bcrypt.checkpw(word.encode("utf-8"), bcrypt_target):
            bcrypt_cracked = word
            break
    bcrypt_time = time.perf_counter() - start_bcrypt
    
    print(f"[Bcrypt] Cracked password: '{bcrypt_cracked}' in {bcrypt_guesses} attempts")
    print(f"[Bcrypt] Total time: {bcrypt_time:.2f} seconds (avg {bcrypt_time / bcrypt_guesses * 1000:.2f} ms per attempt)")
    print(f"[Bcrypt] Estimated speed: ~{bcrypt_guesses / max(bcrypt_time, 1e-9):.2f} hashes/second")
    print("-" * 65)
    
    speed_ratio = (bcrypt_time / bcrypt_guesses) / max(sha_time / sha_guesses, 1e-9)
    print(f"SUMMARY: Bcrypt is approximately {speed_ratio:,.0f}x SLOWER than raw SHA-256.")
    print("This deliberate slowness makes offline brute-force and dictionary attacks computationally infeasible.\n")


def demo_sqli_resistance():
    print("=" * 65)
    print("DEMO 3: SQL INJECTION RESISTANCE TEST")
    print("=" * 65)
    sqli_payload = "' OR 1=1 --"
    print(f"Testing input username: {sqli_payload}")
    
    user = db.get_user_by_username(sqli_payload)
    if user:
        print("[!] Vulnerable: Payload triggered unauthorized access!")
    else:
        print("[OK] Secure: Parameterized query treated input as literal string.")
        print("     No SQL injection occurred!")
    print("=" * 65 + "\n")


def seed_sample_users():
    """Seed test users into database.db to facilitate lab demonstration."""
    print("Initializing database and seeding sample users...")
    db.init_db()
    
    # Register two users with identical password to show salting
    sample_pw = "LabPassword@2026"
    pepper = b"PepperKey!2026#SecureLoginLab"
    
    hash_alice = bcrypt.hashpw(sample_pw.encode("utf-8") + pepper, bcrypt.gensalt(rounds=12)).decode("utf-8")
    hash_bob = bcrypt.hashpw(sample_pw.encode("utf-8") + pepper, bcrypt.gensalt(rounds=12)).decode("utf-8")
    
    db.create_user("alice", hash_alice)
    db.create_user("bob", hash_bob)
    print("[OK] Seeded user 'alice' (password: LabPassword@2026)")
    print("[OK] Seeded user 'bob' (password: LabPassword@2026)")
    print("[OK] Database is ready for web testing.\n")


if __name__ == "__main__":
    seed_sample_users()
    demo_salting()
    demo_cracking_speed_benchmark()
    demo_sqli_resistance()
