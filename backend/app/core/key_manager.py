"""Persistent cryptographic key management for ACPG."""
import os
import json
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from .config import settings


class PersistentKeyManager:
    """
    Manages persistent signing keys for proof bundles.
    
    Keys can be stored:
    1. On filesystem (default, for single-instance deployments)
    2. In environment variables (for containerized deployments)
    3. In a secrets manager (future: AWS KMS, HashiCorp Vault)
    """
    
    DEFAULT_KEY_PATH = Path(__file__).parent.parent.parent / "keys"
    
    def __init__(self, key_path: Optional[Path] = None):
        self.key_path = key_path or self.DEFAULT_KEY_PATH
        self.key_path.mkdir(exist_ok=True)
        
        self._private_key = None
        self._public_key = None
        self._key_id = None
    
    def get_or_create_signing_key(self, key_id: str = "default"):
        """
        Get existing signing key or create new one.
        
        Args:
            key_id: Identifier for the key (allows multiple keys)
        """
        self._key_id = key_id
        private_key_path = self.key_path / f"{key_id}_private.pem"
        public_key_path = self.key_path / f"{key_id}_public.pem"
        
        # Check environment variable first
        env_private_key = os.environ.get(f"ACPG_SIGNING_KEY_{key_id.upper()}")
        if env_private_key:
            self._private_key = serialization.load_pem_private_key(
                env_private_key.encode(),
                password=None,
                backend=default_backend()
            )
            self._public_key = self._private_key.public_key()
            return
        
        # Check filesystem
        if private_key_path.exists():
            with open(private_key_path, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                    backend=default_backend()
                )
            self._public_key = self._private_key.public_key()
            return
        
        # Create new key pair
        self._private_key = ec.generate_private_key(
            ec.SECP256R1(),
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()
        
        # Save to filesystem
        self._save_key_pair(private_key_path, public_key_path)
    
    def _save_key_pair(self, private_path: Path, public_path: Path):
        """Save key pair to filesystem."""
        # Private key (no encryption for now - could add password protection)
        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_path, "wb") as f:
            f.write(private_pem)
        
        # Set restrictive permissions on private key
        os.chmod(private_path, 0o600)
        
        # Public key
        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(public_path, "wb") as f:
            f.write(public_pem)
    
    @property
    def private_key(self):
        """Get private key (loads if needed)."""
        if self._private_key is None:
            self.get_or_create_signing_key()
        return self._private_key
    
    @property
    def public_key(self):
        """Get public key (loads if needed)."""
        if self._public_key is None:
            self.get_or_create_signing_key()
        return self._public_key
    
    def get_public_key_pem(self) -> str:
        """Get public key in PEM format for distribution."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
    
    def get_key_info(self) -> dict:
        """Get information about the current signing key."""
        import hashlib
        
        public_pem = self.get_public_key_pem()
        fingerprint = hashlib.sha256(public_pem.encode()).hexdigest()[:16]
        
        return {
            "key_id": self._key_id or "default",
            "algorithm": "ECDSA-P256",
            "fingerprint": fingerprint,
            "public_key": public_pem
        }
    
    def rotate_key(self, new_key_id: str) -> dict:
        """
        Rotate to a new signing key.
        
        Returns info about the new key.
        """
        self._private_key = None
        self._public_key = None
        self.get_or_create_signing_key(new_key_id)
        return self.get_key_info()
    
    def export_public_key(self, output_path: Path):
        """Export public key to a file for external verifiers."""
        public_pem = self.get_public_key_pem()
        with open(output_path, "w") as f:
            f.write(public_pem)
        return output_path


# Global key manager instance
_key_manager: Optional[PersistentKeyManager] = None


def get_key_manager() -> PersistentKeyManager:
    """Get or create the global key manager."""
    global _key_manager
    if _key_manager is None:
        _key_manager = PersistentKeyManager()
        _key_manager.get_or_create_signing_key()
    return _key_manager

