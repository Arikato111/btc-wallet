# Bitcoin Key Generator

A C-based tool for generating Bitcoin keys from passwords using cryptographic primitives.

## Project Structure
```
bitcoin/
├── include/
│   ├── base.h   # Base58 encoding declarations
│   ├── hash.h   # SHA-256 hashing declarations
│   └── hex.h    # Hexadecimal conversion declarations
└── src/
    ├── main.c   # Main program and key generation logic
    ├── base.c   # Base58 encoding implementation
    ├── hash.c   # SHA-256 hashing implementation
    └── hex.c    # Hexadecimal conversion implementation
```

## Dependencies
- OpenSSL development libraries
- C compiler (gcc/clang)
- Make build system

## Building
1. Install dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install libssl-dev

# Fedora
sudo dnf install openssl-devel
```

2. Build the project:
```bash
make
```

### Usage
Generate a Bitcoin key from a password:
```bash
./build/bitcoin <password>
```

## Docker Usage

Run from github registry

```bash
docker run --rm --name btc-wallet --net=none ghcr.io/arikato111/btc-wallet <password>
```

Build and run using Docker:
```bash
# Build the Docker image
docker build -t btc-wallet .

# Run the container
docker run --rm --name btc-wallet --net=none btc-wallet <password>
```

## Features
- Password-based key generation
- SHA-256 hashing
- Base58 encoding
- secp256k1 elliptic curve operations
- Secure memory handling

## Implementation Details
The project uses:
- OpenSSL for cryptographic operations
- Base58 encoding for Bitcoin address compatibility
- Proper memory management for sensitive data
- Error handling for cryptographic operations

## Security
- Passwords are immediately hashed
- Sensitive data is properly cleaned from memory
- Uses industry-standard cryptographic primitives

## License
GNU General Public License v3.0 (GPL-3.0)
