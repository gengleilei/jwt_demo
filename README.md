# Code Samples: Using PyJWT to Verify and Create JWTs

This repo contains the code used to learn how to create and verify JWTs using Python and PyJWT. ;)

## Prerequisites

- Python >= 3.6

## Setup

Grab the repo and install the dependencies.

```bash
pip install -U pip
pip install -r requirements.txt
```

## Running scripts

```console
python examples/okp.py
```

## Scripts Description

| Script | Description |
| ------ | ----------- |
| `examples/hs256.py` | Creates and prints out a JWT using the **HS256** algorithm |
| `examples/rs256.py` | Creates and prints out a JWT using the **RS256** algorithm |
| `examples/es256.py` | Creates and prints out a JWT using the **ES256** algorithm |
| `examples/okp.py` | Creates and prints out a JWT using the **Ed25519** algorithm |
