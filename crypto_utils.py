from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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
        padded_message = message.encode() + b'\0' * (16 - len(message.encode()) % 16)
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode()

    @staticmethod
    def decrypt_message(encrypted_message, key):
        data = base64.b64decode(encrypted_message)
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        return padded_message.rstrip(b'\0').decode()

    @staticmethod
    def generate_rsa_keypair():
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
    
    # 1. Gjenerimi i çelësave për dy persona
private_A = CryptoCore.generate_ecdh_keypair()
public_A = private_A.public_key()

private_B = CryptoCore.generate_ecdh_keypair()
public_B = private_B.public_key()

# 2. Ana dhe Beni krijojnë të njëjtin çelës sekret (shared_key)
key_for_A = CryptoCore.generate_shared_secret(private_A, public_B)
key_for_B = CryptoCore.generate_shared_secret(private_B, public_A)

# Vërtetimi: key_for_A == key_for_B (duhet të jenë identikë)

# 3. Enkriptimi i një mesazhi
mesazhi_origjinal = "Tung, ky është një mesazh sekret!"
koduar = MessageCipher.encrypt_message(mesazhi_origjinal, key_for_A)
print(f"Mesazhi i enkriptuar: {koduar}")

# 4. Dekriptimi
dekoduar = MessageCipher.decrypt_message(koduar, key_for_B)
print(f"Mesazhi i dekriptuar: {dekoduar}")
