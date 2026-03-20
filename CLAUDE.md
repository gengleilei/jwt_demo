# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a PyJWT learning repository containing code samples for creating and verifying JWTs using different signing algorithms. Each example script demonstrates a specific algorithm implementation.

## Setup

Install dependencies:
```bash
pip install -r requirements.txt
```

Dependencies: PyJWT, cryptography, pycryptodome, requests, rsa

## Running Examples

Execute individual example scripts from the examples directory:

```bash
# HMAC SHA-256 (symmetric)
python examples/hs256.py

# HMAC SHA-384 (symmetric)
python examples/hs384.py

# RSA SHA-256 (asymmetric)
python examples/rs256.py

# RSA SHA-384
python examples/rs384.py

# RSA SHA-512
python examples/rs512.py

# ECDSA P-256
python examples/es256.py

# RSA-PSS SHA-256
python examples/ps256.py

# Ed25519 (EdDSA)
python examples/okp.py

# RSA-PSS SHA-384
python examples/ps384.py
```

## Testing

Run the existing unit tests:
```bash
# Run all tests with pytest
pytest examples/

# Run specific test file
python examples/ps384_test.py

# Run single test class
python -m unittest examples.ps384_test.TestGeneratePS384JWKS

# Run single test method
python -m unittest examples.ps384_test.TestGeneratePS384JWKS.test_generate_ps384_jwks_valid_use
```

## Code Architecture

### Example Script Structure

Each example follows a consistent pattern:

1. **Key Generation**: Generate cryptographic key pairs (RSA, EC, Ed25519) or use shared secrets (HMAC)
2. **Token Creation**: Use `jwt.encode()` with the private key/secret and algorithm
3. **JWKS Generation**: Build JWKS (JSON Web Key Set) from public key for key distribution
4. **Test Function**: Optional HTTP test with Bearer token (target URL needs configuration)

### Key Patterns

**RSA-based algorithms (RS256, RS384, RS512, PS256, PS384)**:
- Generate 2048-bit RSA key pairs using `cryptography.hazmat.primitives.asymmetric.rsa`
- JWKS contains `kty: "RSA"`, base64url-encoded modulus (`n`), and exponent (`e`)

**ECDSA algorithms (ES256)**:
- Generate P-256 elliptic curve keys using `cryptography.hazmat.primitives.asymmetric.ec`
- JWKS contains `kty: "EC"`, curve (`crv: "P-256"`), and base64url-encoded x/y coordinates

**EdDSA (Ed25519)**:
- Generate Ed25519 keys using `cryptography.hazmat.primitives.asymmetric.ed25519`
- JWKS contains `kty: "OKP"`, curve (`crv: "Ed25519"`), and base64url-encoded public key

**HMAC (HS256, HS384)**:
- Use shared secret string
- HS256 and HS384 use the same key type (`kty: "oct"`)
- JWKS contains `kty: "oct"` and base64-encoded key

### Common Payload Fields

Standard JWT payload claims used across examples:
- `iss` (Issuer): Set to "test"
- `sub` (Subject): Set to "test"
- `iat` (Issued At): Current UTC time
- `exp` (Expiration): 30 minutes from issuance

### Important Notes

- Example scripts print the JWT token, PEM keys, and JWKS JSON to stdout
- The `test()` function in examples uses a placeholder IP (`http://xx.xx.xx.xx/headers`) that must be configured for actual testing
- `ps384_test.py` contains unit tests for the PS384 implementation using Python's unittest framework
