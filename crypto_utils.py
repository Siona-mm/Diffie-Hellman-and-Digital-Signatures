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
    
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

class MessageCipher:
    @staticmethod
    def encrypt_message(message, key):
        iv = os.urandom(16)  # Initialization Vector unik për çdo enkriptim
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Shtohet padding (PKCS7) që mesazhi të jetë i plotësuar për bllokun 128-bit
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        # Bashkojmë IV dhe ciphertext në një string Base64
        return base64.b64encode(iv + ciphertext).decode()

    @staticmethod
    def decrypt_message(encrypted_message, key):
        data = base64.b64decode(encrypted_message)
        iv = data[:16]
        ciphertext = data[16:]
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Dekriptimi
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Heqja e padding
        unpadder = padding.PKCS7(128).unpadder()
        message = unpadder.update(padded_data) + unpadder.finalize()
        return message.decode()
    
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