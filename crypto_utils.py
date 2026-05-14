from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os
import base64

class CryptoUtils:
    @staticmethod
    def generate_ecdh_keypair():
        return ec.generate_private_key(ec.SECP256R1(), default_backend())

    @staticmethod
    def generate_shared_secret(private_key, peer_public_key):
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        return derived_key

    @staticmethod
    def encrypt_message(message, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Përdorimi i PKCS7 padding (më i sigurt se manuali me \0)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    @staticmethod
    def decrypt_message(encrypted_message, key):
        data = base64.b64decode(encrypted_message)
        iv, ciphertext = data[:16], data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Heqja e padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        message = unpadder.update(padded_message) + unpadder.finalize()
        return message.decode()

# --- EKZEKUTIMI I KODIT ---

# 1. Gjenerimi i çelësave (Përdorim emrin e saktë të klasës: CryptoUtils)
private_A = CryptoUtils.generate_ecdh_keypair()
public_A = private_A.public_key()

private_B = CryptoUtils.generate_ecdh_keypair()
public_B = private_B.public_key()

# 2. Krijimi i sekretit të përbashkët
key_for_A = CryptoUtils.generate_shared_secret(private_A, public_B)
key_for_B = CryptoUtils.generate_shared_secret(private_B, public_A)

# 3. Enkriptimi
mesazhi_origjinal = "Tung, ky është një mesazh sekret!"
koduar = CryptoUtils.encrypt_message(mesazhi_origjinal, key_for_A)
print(f"Mesazhi i enkriptuar: {koduar}")

# 4. Dekriptimi
dekoduar = CryptoUtils.decrypt_message(koduar, key_for_B)
print(f"Mesazhi i dekriptuar: {dekoduar}")
