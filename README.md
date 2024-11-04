Post Quantum Password Manager in Python

This is one of my biggest projects in Python to prepare for my bachelor's degree in Cyber ​​Security.

It includes the following cryptographic properties:

AES (Advanced Encryption Standard) for symmetric encryption

PBKDF2 (Password-Based Key Derivation Function 2) for key derivation

SHA-256 as hash function

Fernet (based on AES-CBC) for data encryption


To Do:

Integration of post-quantum algorithms:

with CRYSTALS-Kyber (a post-quantum KEM)

SPHINCS+ for digital signatures

from pqcrypto.sign.sphincs import generate_keypair, sign, verify

Use of quantum-safe hash functions: SHAKE256 or SHA3 instead of SHA256

from cryptography.hazmat.primitives.hashes import SHAKE256

Implementation of quantum-safe key derivation

Hybrid encryption (classic + Post-Quantum)

Secure random number generation

So:

Incorporate post-quantum cryptography libraries

Adapt the encryption logic

Implement hybrid encryption approaches

Use quantum-safe key derivation functions

Improve random number generation
