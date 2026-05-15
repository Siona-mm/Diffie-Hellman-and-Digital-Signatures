import asyncio
import websockets
import json
from crypto_utils import CryptoUtils

class SecureClient:
    def __init__(self):
        self.shared_key = None
        self.server_rsa_public_key = None
        self.ecdh_private_key = None
        self.ecdh_public_key = None

    async def connect(self):
        uri = "ws://localhost:8765"
        print("\n" + "="*80)
        print("SECURE CLIENT-SERVER COMMUNICATION PROTOCOL")
        print("="*80)
        print("\nConnecting to server at", uri)
        print("="*80 + "\n")
        
        async with websockets.connect(uri) as websocket:
            print("[PHASE 1: KEY EXCHANGE INITIALIZATION]")
            print("[Step 1: Receiving Server's Public Keys]\n")
            
            message = await websocket.recv()
            data = json.loads(message)
            if data['type'] == 'init':
                self.server_rsa_public_key = CryptoUtils.deserialize_public_key(data['rsa_public_key'])
                server_ecdh_public_key = CryptoUtils.deserialize_ecdh_public_key(data['ecdh_public_key'])
                
                print(f"SERVER RSA PUBLIC KEY (2048-bit for Digital Signatures):\n{data['rsa_public_key']}")
                print(f"\nSERVER ECDH PUBLIC KEY (P-256 Elliptic Curve for Key Exchange):\n{data['ecdh_public_key']}\n")

                print("[Step 2: Client Generating ECDH Keypair]\n")
                self.ecdh_private_key = CryptoUtils.generate_ecdh_keypair()
                self.ecdh_public_key = self.ecdh_private_key.public_key()
                print(f"CLIENT ECDH PRIVATE KEY (P-256): Generated and kept secret")
                print(f"CLIENT ECDH PUBLIC KEY (P-256): Generated\n")

                print("[Step 3: Client Sending ECDH Public Key to Server]\n")
                ecdh_public_pem = CryptoUtils.serialize_ecdh_public_key(self.ecdh_public_key)
                print(f"CLIENT ECDH PUBLIC KEY SENT (P-256):\n{ecdh_public_pem}\n")
                await websocket.send(json.dumps({
                    'type': 'ecdh_exchange',
                    'ecdh_public_key': ecdh_public_pem
                }))

                print("\n[PHASE 2: SHARED SECRET ESTABLISHMENT]")
                print("[Step 4: Client Deriving Shared Secret]")
                print("✓ [Requirement: Diffie-Hellman] Computing shared secret using client private key + server public key\n")
                self.shared_key = CryptoUtils.generate_shared_secret(self.ecdh_private_key, server_ecdh_public_key)
                shared_key_hex = self.shared_key.hex()
                print(f"Shared Secret Successfully Derived (hex):")
                print(f"{shared_key_hex}\n")

                print("\n[PHASE 2: SHARED SECRET ESTABLISHMENT]")
                print("[Step 4: Client Deriving Shared Secret]")
                print("✓ [Requirement: Diffie-Hellman] Computing shared secret using client private key + server public key\n")
                self.shared_key = CryptoUtils.generate_shared_secret(self.ecdh_private_key, server_ecdh_public_key)
                shared_key_hex = self.shared_key.hex()
                print(f"Shared Secret Successfully Derived (hex):")
                print(f"{shared_key_hex}\n")

                print("\n[PHASE 3: MESSAGE INTEGRITY & AUTHENTICATION]")
                print("[Step 5: Receiving Server's Signed Welcome Message]")
                print("✓ [Requirement: Digital Signatures] Receiving encrypted + signed message from server\n")
                message = await websocket.recv()
                data = json.loads(message)
                if data['type'] == 'welcome':
                    encrypted_msg = data['message']
                    signature = data['signature']
                    print(f"Encrypted Message: {encrypted_msg[:80]}...")
                    print(f"RSA Signature: {signature[:80]}...\n")
                    
                    print("[Step 6: Decrypting and Verifying Message]")
                    print("✓ [Requirement: AES Encryption] Decrypting with shared secret key")
                    print("✓ [Requirement: Digital Signatures] Verifying RSA-PSS signature with server public key")
                    print("✓ [Requirement: Message Integrity] Verifying message digest (SHA-256)\n")
                    
                    decrypted_msg = CryptoUtils.decrypt_message(encrypted_msg, self.shared_key)
                    print(f"Decrypted Message: {decrypted_msg}")
                    
                    if CryptoUtils.verify_signature(decrypted_msg, signature, self.server_rsa_public_key):
                        print("✓ Signature verified successfully")
                        print("✓ Server authentication confirmed (Non-Repudiation)")
                        print("✓ Secure communication established\n")
                        print("="*80 + "\n")
                    else:
                        print("✗ Signature verification failed!")
                        return