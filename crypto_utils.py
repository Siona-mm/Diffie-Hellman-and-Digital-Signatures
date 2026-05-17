from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

class CryptoUtils:
    # PHASEN 1 & 2: DIFFIE-HELLMAN KEY EXCHANGE
    @staticmethod
    def generate_ecdh_keypair():
        # Gjeneron ciftin e çelsave (privat/publik) duke perdorur kurben eliptike P-256 (SECP256R1)
        return ec.generate_private_key(ec.SECP256R1(), default_backend())

    @staticmethod
    def generate_shared_secret(private_key, peer_public_key):
        # Llogarit sekretin e perbashket (celsi privat imi + celsi publik i pales tjeter)
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        # HKDF me SHA-256 e kthen kete sekret ne nje cels te paster 256-bit per AES-256
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        return derived_key

   # ENKRIPTIMI SIMETRIK (AES-CBC)

    @staticmethod
    def encrypt_message(message, key):
        # Ktu gjenetrohet nje IV (Initialization Vector) i rastesishem 16-bajtesh per siguri shtese
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        # AES kerkon blloqe 16-bajtesh, prandaj shtohet padding manual me '\0' ne fund
        padded_message = message.encode() + b'\0' * (16 - len(message.encode()) % 16)
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        # Ngjit IV-ne ne fillim te mesazhit dhe e kodon ne Base64 qe te transmetohet si tekst
        return base64.b64encode(iv + ciphertext).decode()

    @staticmethod
    def decrypt_message(encrypted_message, key):
        # Dekodon nga Base64 dhe ndan IV-ne (16 bajtat e pare) nga ciphertext-i
        data = base64.b64decode(encrypted_message)
        iv = data[:16]
        ciphertext = data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        # Dekripton mesazhin dhe fshin karakteret '\0' (padding-un) qe u shtuan ne fillim
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        return padded_message.rstrip(b'\0').decode()

   # NENSHKRIMET DIXHITALE (RSA-PSS)

    @staticmethod
    def generate_rsa_keypair():
        # Gjeneron ciftin e celsave RSA 2048-bit (perdoret vetem per Autentikim dhe Mos-mohim)
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    @staticmethod
    def sign_message(message, private_key):
        # Serveri nenshkruan mesazhin me celsin e tij privat RSA-PSS (bohet hash me SHA-256)
        signature = private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    @staticmethod
    def verify_signature(message, signature, public_key):
        # Klienti verifikon nenshkrimin me celsin publik te serverit (Garanton Integritetin dhe Autenticitetin)
        try:
            public_key.verify(
                base64.b64decode(signature),
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

     # METODAT NDIHMESE
     # Kthejne objektet e celsave ne formatin tekstual PEM (dhe anasjelltas) qe te dergohen leht ne rrjet permes JSON

    @staticmethod
    def serialize_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

   
    @staticmethod
    def deserialize_public_key(pem_data):
        return serialization.load_pem_public_key(
            pem_data.encode(),
            backend=default_backend()
        )

    
    @staticmethod
    def serialize_ecdh_public_key(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    @staticmethod
    def deserialize_ecdh_public_key(pem_data):
        return serialization.load_pem_public_key(
            pem_data.encode(),
            backend=default_backend()
        )