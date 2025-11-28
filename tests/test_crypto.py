"""Tests for cryptography utilities."""
import pytest
from backend.app.core.crypto import ProofSigner


def test_proof_signer_initialization():
    """Test that ProofSigner initializes with key pair."""
    signer = ProofSigner()
    assert signer.private_key is not None
    assert signer.public_key is not None


def test_compute_hash():
    """Test SHA-256 hash computation."""
    signer = ProofSigner()
    data = "test data"
    hash1 = signer.compute_hash(data)
    hash2 = signer.compute_hash(data)
    
    # Same data should produce same hash
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA-256 produces 64 hex characters


def test_sign_and_verify_proof():
    """Test signing and verification of proof bundles."""
    signer = ProofSigner()
    
    proof_data = {
        "artifact": {
            "name": "test.py",
            "hash": "abc123",
            "language": "python"
        },
        "decision": "Compliant"
    }
    
    # Sign the proof
    signature = signer.sign_proof(proof_data)
    assert signature is not None
    assert len(signature) > 0
    
    # Verify the signature
    is_valid = signer.verify_signature(proof_data, signature)
    assert is_valid is True


def test_verify_fails_with_wrong_data():
    """Test that verification fails with tampered data."""
    signer = ProofSigner()
    
    original_data = {"decision": "Compliant"}
    signature = signer.sign_proof(original_data)
    
    # Tamper with data
    tampered_data = {"decision": "Non-compliant"}
    
    # Verification should fail
    is_valid = signer.verify_signature(tampered_data, signature)
    assert is_valid is False


def test_get_public_key_pem():
    """Test public key export in PEM format."""
    signer = ProofSigner()
    pem = signer.get_public_key_pem()
    
    assert pem is not None
    assert "BEGIN PUBLIC KEY" in pem
    assert "END PUBLIC KEY" in pem


def test_get_public_key_fingerprint():
    """Test public key fingerprint generation."""
    signer = ProofSigner()
    fingerprint = signer.get_fingerprint()
    
    assert fingerprint is not None
    assert len(fingerprint) == 16  # First 16 chars of hash
    assert fingerprint.isalnum()
