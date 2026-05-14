from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os
import base64

class CryptoCore:
    @staticmethod
    def generate_ecdh_keypair():
        # Krijon çelësin privat për ECDH (Curve P-256)
        return ec.generate_private_key(ec.SECP256R1(), default_backend())

    @staticmethod
    def generate_shared_secret(private_key, peer_public_key):
        # Shkëmbejnë çelësat për të nxjerrë një "shared secret"
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        
        # HKDF e kthen këtë sekret në një çelës fiks 32-byte (për AES-256)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        return derived_key
    