# FIDO2 Protocol Implementation Sample

This project implements various FIDO2 protocol schemes for authentication and registration. It provides a comprehensive test environment for different FIDO2 protocol implementations.

## Project Structure

### Core Protocol Implementations
- `SchemeBip32.java`: Basic BIP32 protocol implementation
- `SchemeBip32Mu.java`: BIP32MU protocol implementation
- `SchemeBip32Su.java`: BIP32SU protocol implementation
- `SchemeBip32MuPlus.java`: Enhanced BIP32MU protocol implementation
- `SchemeBip32SuPlus.java`: Enhanced BIP32SU BIP32 protocol implementation
- `SchemeBip32Plus.java`: Enhanced BIP32 protocol implementation

### Main Components
- `MainActive.java`: Main entry point of the application
- `FidoProtocolFactory.java`: Factory class for managing protocol implementations
- `FidoServerFactory.java`: Factory class for server-side operations
- `CustomCryptoUtils.java`: Utility class for cryptographic operations

### Activities
- `PerformanceTestActivity.java`: Interface for performance testing
- `SettingsActivity.java`: Application settings interface

## Workflow

1. **Application Launch**
   - The app starts with `MainActive` as the main entry point
   - Initializes the FIDO server and protocol factory
   - Displays the main interface with various test options

2. **Protocol Selection**
   - Select from six different protocol implementations
   - Each protocol provides registration and authentication capabilities

3. **Testing Features**
   - Registration: Test user registration with selected protocol
   - Authentication: Test user authentication with selected protocol
   - Performance Testing: Measure protocol performance metrics
   - Settings: Configure application parameters

4. **Protocol Operations**
   - Registration: Generates challenges, computes commitments, and verifies responses
   - Authentication: Handles challenge-response authentication flow
   - Each protocol implementation follows the FIDO2 specification with specific optimizations

# BIP32 Revocation System

This project implements a revocation system based on BIP32PA with two different approaches.

## Project Structure

- `bip32mu_revoke.py`: Implementation of the bip32mu revocation system
- `bip32pa_revoke.py`: Implementation of the bip32pa revocation system
- `revoke0.py`: Test implementation for the basic revocation system
- `revoke1.py`: Enhanced test implementation with additional features
- `revocation_test0.py`: Test cases for the basic revocation system
- `revocation_test1.py`: Test cases for the enhanced revocation system

## Main Components

### BIP32MURevoke
- Implements a revocation system with unbounded memory requirements
- Features:
  - Master key generation
  - Revocation key generation
  - Credential checking
  - Performance simulation

### BIP32PARevoke
- Implements a revocation system with public-key anonymity
- Features:
  - Master key generation
  - Revocation key generation
  - Anonymous credential checking
  - Performance simulation

## Usage

1. Install the required dependencies:
```bash
pip install ecdsa pycryptodome
```

2. Run the test files to verify the implementation:
```bash
python revocation_test0.py
python revocation_test1.py
```



