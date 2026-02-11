> [!NOTE]
> Documentation Refresh Note (February 11, 2026): this file is retained as specialized or historical context.
> For current product behavior and authoritative guidance, start at /Users/James/code/GAD/apcg/README.md and /Users/James/code/GAD/apcg/docs/README.md.

# Tamper Detection in Proof Bundles

## Overview

ACPG proof bundles are designed to be tamper-proof. The code artifact is cryptographically signed and included in the bundle, ensuring that any modification to the code, policies, evidence, or argumentation will be detected.

## How It Works

### 1. Code Inclusion

The proof bundle includes:
- **Artifact Metadata**: Hash, language, generator, timestamp
- **Code**: The actual code artifact (newly included)
- **Policies**: Policy outcomes (satisfied/violated)
- **Evidence**: Evidence traces from analysis
- **Argumentation**: Formal reasoning trace
- **Decision**: Compliant/Non-compliant
- **Signature**: Cryptographic signature covering all of the above

### 2. Cryptographic Signing

The signature covers **all bundle data**, including:
```json
{
  "artifact": {...},
  "code": "...",  // ← Code is included in signature
  "policies": [...],
  "evidence": [...],
  "argumentation": {...},
  "decision": "...",
  "timestamp": "..."
}
```

**Algorithm**: ECDSA with SHA-256
- Uses persistent signing keys (stored securely)
- Public key fingerprint included in bundle
- Canonical JSON serialization (sorted keys)

### 3. Verification Process

When verifying a proof bundle:

1. **Signature Verification**
   - Reconstructs the signed data structure
   - Verifies ECDSA signature against public key
   - If signature fails → bundle has been tampered with

2. **Code Hash Verification**
   - Computes SHA-256 hash of included code
   - Compares with artifact hash in metadata
   - If hash mismatch → code has been modified

3. **Complete Integrity Check**
   - Signature valid + Hash matches = Bundle is authentic
   - Signature invalid OR Hash mismatch = Bundle has been tampered with

## Security Guarantees

### What's Protected

✅ **Code**: Any modification to code invalidates signature
✅ **Policies**: Policy outcomes cannot be changed
✅ **Evidence**: Evidence cannot be modified
✅ **Argumentation**: Reasoning trace cannot be altered
✅ **Decision**: Decision cannot be changed
✅ **Metadata**: Artifact metadata is protected

### Attack Scenarios

#### Scenario 1: Code Modification
```
Original: code = "print('hello')"
Modified: code = "print('hacked')"
Result: ❌ Signature invalid (code changed)
```

#### Scenario 2: Policy Outcome Tampering
```
Original: policies = [{"id": "SQL-001", "result": "violated"}]
Modified: policies = [{"id": "SQL-001", "result": "satisfied"}]
Result: ❌ Signature invalid (policies changed)
```

#### Scenario 3: Hash Mismatch
```
Original: hash = sha256(code) = "abc123..."
Modified: code changed but hash not updated
Result: ❌ Hash mismatch (code != hash)
```

#### Scenario 4: Signature Replacement
```
Original: signature = sign(private_key, bundle_data)
Modified: signature = sign(different_key, bundle_data)
Result: ❌ Signature invalid (wrong key)
```

## Usage

### Generating a Proof Bundle

```python
from app.services.proof_assembler import get_proof_assembler

proof_assembler = get_proof_assembler()
bundle = proof_assembler.assemble_proof(
    code=code,  # Code is included in bundle
    analysis=analysis,
    adjudication=adjudication,
    language="python"
)

# Bundle now includes:
# - bundle.code (the actual code)
# - bundle.artifact.hash (SHA-256 hash of code)
# - bundle.signed.signature (covers code + everything else)
```

### Verifying a Proof Bundle

```python
# Method 1: Using proof assembler
is_valid = proof_assembler.verify_proof(bundle)
# Returns True if:
#   - Signature is valid
#   - Code hash matches artifact hash

# Method 2: Using API endpoint
POST /api/v1/proof/verify
{
  "proof_bundle": {...}
}

# Returns:
{
  "valid": true/false,
  "tampered": false/true,
  "details": {
    "signature_valid": true,
    "hash_valid": true,
    "code_present": true
  },
  "checks": [
    "✓ Code content present (1234 characters)",
    "✓ Code hash matches artifact hash (code integrity verified)",
    "✓ ECDSA signature is VALID"
  ]
}
```

## Verification Details

### What Gets Checked

1. **Code Presence**: Is code included in bundle?
2. **Signature Validity**: Does signature match signed data?
3. **Hash Match**: Does code hash match artifact hash?
4. **Signer Match**: Does signer fingerprint match expected key?
5. **Timestamp**: Is timestamp present and valid?

### Verification Output

**Valid Bundle**:
```
✓ Code content present (1234 characters)
✓ Artifact hash present: abc123def456...
✓ Code hash matches artifact hash (code integrity verified)
✓ ECDSA signature is VALID
✓ Signer fingerprint matches: 516e29c929b926fb

═══════════════════════════════════════
  ✓ PROOF BUNDLE INTEGRITY VERIFIED
  This bundle has NOT been tampered with
═══════════════════════════════════════
```

**Tampered Bundle**:
```
✓ Code content present (1234 characters)
✓ Artifact hash present: abc123def456...
✗ Code hash MISMATCH - code has been modified!
  Expected: abc123def456...
  Computed: xyz789ghi012...
✗ Signature verification FAILED: Invalid signature
  The proof bundle data has been modified since signing

═══════════════════════════════════════
  ✗ PROOF BUNDLE TAMPERING DETECTED
  This bundle has been modified!
═══════════════════════════════════════
```

## Best Practices

1. **Always Verify**: Verify proof bundles before trusting them
2. **Check Both**: Signature AND hash must be valid
3. **Store Securely**: Keep proof bundles in secure storage
4. **Verify Public Key**: Ensure you're using the correct public key
5. **Check Timestamps**: Verify timestamps are reasonable

## Technical Details

### Signature Algorithm
- **Algorithm**: ECDSA (Elliptic Curve Digital Signature Algorithm)
- **Curve**: SECP256R1 (P-256)
- **Hash**: SHA-256
- **Encoding**: Base64

### Hash Algorithm
- **Algorithm**: SHA-256
- **Input**: Code content (UTF-8 encoded)
- **Output**: Hexadecimal string (64 characters)

### Key Management
- Keys are stored persistently in `backend/.keys/`
- Private key is encrypted at rest
- Public key fingerprint is included in bundle for identification
- Keys can be rotated (new bundles will have new fingerprint)

## Example: Tamper Detection

```python
# Original bundle
bundle = assemble_proof(code="print('hello')", ...)
assert verify_proof(bundle) == True  # ✓ Valid

# Tamper with code
bundle.code = "print('hacked')"
assert verify_proof(bundle) == False  # ✗ Invalid (signature fails)

# Tamper with hash (but not code)
bundle.artifact.hash = "fake_hash"
assert verify_proof(bundle) == False  # ✗ Invalid (hash mismatch)

# Tamper with policy
bundle.policies[0].result = "satisfied"  # was "violated"
assert verify_proof(bundle) == False  # ✗ Invalid (signature fails)
```

## Conclusion

With code included in the proof bundle and cryptographically signed, ACPG provides strong tamper detection:

- ✅ **Code integrity**: Code cannot be modified
- ✅ **Bundle integrity**: Nothing in bundle can be changed
- ✅ **Self-contained**: Bundle includes everything needed for verification
- ✅ **Cryptographically secure**: Uses industry-standard ECDSA signatures

Any attempt to modify the code, policies, evidence, or argumentation will invalidate the signature and be detected during verification.

