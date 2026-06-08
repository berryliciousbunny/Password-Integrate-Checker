## 1. Introduction & threat model

This project assumes you want to check *password integrity* in two senses:

- **Correctness & safety of password storage**: That passwords are hashed with a modern algorithm, with per-password salt and parameters configured for cost/time-memory resistance.
- **User password quality and compromise check**: That chosen passwords are strong enough (entropy/guessability) and not present in known breach datasets.

Threat model (brief):

- Attacker who gets read access to the password database: we must make offline attacks expensive using Argon2 (or bcrypt if Argon2 not available).
- Attacker who tries to guess weak passwords: enforce/score strength, detect commonly used/compromised ones.

This project does **not** cover multi-factor authentication, brute-force prevention on live login endpoints, or client-side password managers for being out-of-scope.

## 2. Features

- Password strength scoring (zxcvbn-style heuristics + simple policy checks).
- Check password against Have I Been Pwned (HIBP) Pwned Passwords API using k-anonymity.
- Secure hashing using Argon2 (via `argon2-cffi`) and a configurable fallback to bcrypt (via `bcrypt` or `passlib`).
- Simple SQLite-backed storage of user records and hashed passwords.
- Audit script to list weak/compromised passwords in the user DB.
- Command-line interface for adding users, verifying, and auditing.
- Unit tests with `pytest`.

## 3. Core concepts explained
### Hashing and Salt

Never store plaintext passwords. Use a slow, memory-hard hashing algorithm (Argon2id preferred). Each password should have its own salt — modern libraries handle this for you and include salt inside the encoded hash string.

### Argon2 parameters

Argon2 has parameters: `time_cost` (iterations), `memory_cost` (KiB), and `parallelism`. Choose them so that hashing takes ~100-500ms on your server (tune for your hardware). Example defaults used here are conservative for local testing.

### k-Anonymity for HIBP

We never send full password hashes to the HIBP service. Instead:

1. Hash the password with SHA-1.
2. Send the first 5 hex characters (prefix) to the HIBP range API.
3. Compare suffixes locally to find if the password appears in the dataset.

This leaks only a 5-hex-character prefix and is considered safe by HIBP authors for client-side checks.