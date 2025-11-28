"""Cryptographic utilities for signing proof bundles."""
import json
import base64
import hashlib
from typing import Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


class ProofSigner:
    """Handle cryptographic signing of proof bundles."""
    
    def __init__(self):
        """Initialize with a new key pair."""
        self.private_key = ec.generate_private_key(
            ec.SECP256R1(), 
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def compute_hash(self, data: str) -> str:
        """Compute SHA-256 hash of data."""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def sign_proof(self, proof_data: Dict[str, Any]) -> str:
        """
        Sign a proof bundle.
        
        Args:
            proof_data: Dictionary containing proof data (without signature)
        
        Returns:
            Base64-encoded signature
        """
        # Serialize proof data in canonical form (sorted keys)
        canonical_json = json.dumps(proof_data, sort_keys=True)
        data_bytes = canonical_json.encode('utf-8')
        
        # Sign the data
        signature = self.private_key.sign(
            data_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        
        # Return base64-encoded signature
        return base64.b64encode(signature).decode('utf-8')
    
    def verify_signature(self, proof_data: Dict[str, Any], signature: str) -> bool:
        """
        Verify a signature on proof data.
        
        Args:
            proof_data: Dictionary containing proof data (without signature)
            signature: Base64-encoded signature to verify
        
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Serialize proof data in canonical form
            canonical_json = json.dumps(proof_data, sort_keys=True)
            data_bytes = canonical_json.encode('utf-8')
            
            # Decode signature
            signature_bytes = base64.b64decode(signature)
            
            # Verify
            self.public_key.verify(
                signature_bytes,
                data_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format."""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def get_public_key_fingerprint(self) -> str:
        """Get fingerprint of public key for identification."""
        pem_bytes = self.get_public_key_pem().encode('utf-8')
        return hashlib.sha256(pem_bytes).hexdigest()[:16]


# Global signer instance
_signer = None


def get_signer() -> ProofSigner:
    """Get or create the global proof signer instance."""
    global _signer
    if _signer is None:
        _signer = ProofSigner()
    return _signer
