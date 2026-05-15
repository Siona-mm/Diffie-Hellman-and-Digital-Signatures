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