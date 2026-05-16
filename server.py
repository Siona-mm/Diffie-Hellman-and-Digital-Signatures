import asyncio
import websockets
import json
from crypto_utils import CryptoUtils
import base64

class SecureServer:
    def __init__(self):
        self.clients = {}
        self.rsa_private_key = CryptoUtils.generate_rsa_keypair()
        self.rsa_public_key = self.rsa_private_key.public_key()
        self.ecdh_private_key = CryptoUtils.generate_ecdh_keypair()
        self.ecdh_public_key = self.ecdh_private_key.public_key()
        
        print("\n" + "="*80)
        print("SERVER INITIALIZATION")
        print("="*80)
        print("\n[RSA Key Pair Generated]")
        rsa_public_pem = CryptoUtils.serialize_public_key(self.rsa_public_key)
        print(f"RSA PUBLIC KEY (2048-bit for Digital Signatures):\n{rsa_public_pem}")
        
        print("\n[ECDH Key Pair Generated]")
        ecdh_public_pem = CryptoUtils.serialize_ecdh_public_key(self.ecdh_public_key)
        print(f"ECDH PUBLIC KEY (P-256 Elliptic Curve - Diffie-Hellman):\n{ecdh_public_pem}")
        print("="*80 + "\n")

    async def handle_client(self, websocket, path):
        client_id = id(websocket)
        self.clients[client_id] = {'websocket': websocket, 'shared_key': None}
        print(f"\n{'='*80}")
        print(f"CLIENT CONNECTED: {client_id}")
        print(f"{'='*80}")

        try:
            # Send DH parameters and public key
            print("\n[Step 1: Server Sending Public Keys to Client]")
            ecdh_public_pem = CryptoUtils.serialize_ecdh_public_key(self.ecdh_public_key)
            rsa_public_pem = CryptoUtils.serialize_public_key(self.rsa_public_key)
            print(f"Sending ECDH PUBLIC KEY (P-256):\n{ecdh_public_pem}")
            print(f"Sending RSA PUBLIC KEY (2048-bit):\n{rsa_public_pem}\n")
            
            await websocket.send(json.dumps({
                'type': 'init',
                'ecdh_public_key': ecdh_public_pem,
                'rsa_public_key': rsa_public_pem
            }))

            # Receive client's ECDH public key
            print("[Step 2: Server Receiving Client's ECDH Public Key]")
            message = await websocket.recv()
            data = json.loads(message)
            if data['type'] == 'ecdh_exchange':
                client_ecdh_public_key = CryptoUtils.deserialize_ecdh_public_key(data['ecdh_public_key'])
                print(f"CLIENT ECDH PUBLIC KEY (P-256) RECEIVED:\n{data['ecdh_public_key']}\n")
                
                # Generate shared secret
                print("[Step 3: Server Deriving Shared Secret from ECDH]")
                shared_key = CryptoUtils.generate_shared_secret(self.ecdh_private_key, client_ecdh_public_key)
                self.clients[client_id]['shared_key'] = shared_key
                shared_key_hex = shared_key.hex()
                print(f"DERIVED SHARED SECRET (256-bit hex):")
                print(f"{shared_key_hex}\n")

                # Send signed welcome message
                print("[Step 4: Server Sending Signed Welcome Message (AES + RSA)]")
                welcome_msg = "Welcome to secure communication!"
                signature = CryptoUtils.sign_message(welcome_msg, self.rsa_private_key)
                encrypted_msg = CryptoUtils.encrypt_message(welcome_msg, shared_key)
                print(f"ORIGINAL MESSAGE: {welcome_msg}")
                print(f"\nENCRYPTED MESSAGE (AES-CBC with shared secret):\n{encrypted_msg}")
                print(f"\nDIGITAL SIGNATURE (RSA-PSS 2048-bit with SHA-256):\n{signature}")
                print(f"\nMessage Sent\n")
                
                await websocket.send(json.dumps({
                    'type': 'welcome',
                    'message': encrypted_msg,
                    'signature': signature
                }))
                
                print(f"{'='*80}\n")

            # Handle messages
            async for message in websocket:
                data = json.loads(message)
                if data['type'] == 'message':
                    encrypted_msg = data['message']
                    decrypted_msg = CryptoUtils.decrypt_message(encrypted_msg, self.clients[client_id]['shared_key'])
                    print(f"\n[Message Received from Client {client_id}]")
                    print(f"ENCRYPTED MESSAGE:\n{encrypted_msg}")
                    print(f"\nDECRYPTED MESSAGE: {decrypted_msg}")

                    # Echo back
                    response = f"Server received: {decrypted_msg}"
                    encrypted_response = CryptoUtils.encrypt_message(response, self.clients[client_id]['shared_key'])
                    signature = CryptoUtils.sign_message(response, self.rsa_private_key)
                    print(f"\nRESPONSE MESSAGE: {response}")
                    print(f"\nENCRYPTED RESPONSE:\n{encrypted_response}")
                    print(f"\nRESPONSE SIGNATURE (RSA-PSS):\n{signature}")
                    print(f"\nResponse Sent\n")
                    
                    await websocket.send(json.dumps({
                        'type': 'message',
                        'message': encrypted_response,
                        'signature': signature
                    }))

        except Exception as e:
            print(f"Error: {e}")
        finally:
            del self.clients[client_id]
            print(f"Client disconnected: {client_id}\n")

    async def console_interface(self):
        while True:
            command = await asyncio.get_event_loop().run_in_executor(None, input, "\nServer> ")
            if command.startswith("send "):
                msg = command[5:]
                for client in self.clients.values():
                    if client['shared_key']:
                        print(f"\n[Broadcasting Message to Clients]")
                        print(f"Message: {msg}")
                        encrypted = CryptoUtils.encrypt_message(msg, client['shared_key'])
                        signature = CryptoUtils.sign_message(msg, self.rsa_private_key)
                        print(f"✓ Message encrypted with AES (shared secret)")
                        print(f"✓ Message signed with RSA private key")
                        print(f"✓ Encrypted: {encrypted[:60]}...")
                        print(f"✓ Signature: {signature[:60]}...")
                        await client['websocket'].send(json.dumps({
                            'type': 'message',
                            'message': encrypted,
                            'signature': signature
                        }))
            elif command == "quit":
                print("\nServer shutting down...")
                break

async def main():
    server = SecureServer()
    start_server = websockets.serve(server.handle_client, "localhost", 8765)
    print("\n✓ Server started on ws://localhost:8765")
    print("✓ Listening for client connections...")

    await asyncio.gather(
        start_server,
        server.console_interface()
    )

if __name__ == "__main__":
    asyncio.run(main())