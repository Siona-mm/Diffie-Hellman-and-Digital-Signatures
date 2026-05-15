import asyncio
import websockets
import json
from crypto_utils import CryptoUtils

class SecureClient:
    # Inicializimi i variablave ku do te ruhen celsat gjate sesionit
    def __init__(self):
        self.shared_key = None # Celsi simetrik i perbashket (AES)
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
        
        # Per me kriju lidhjen asinkrone me serverin permes protokollit Websocket
        async with websockets.connect(uri) as websocket:

            # FAZA 1: INITIALIZATION & PUBLIC KEY EXCHANGE
            print("[PHASE 1: KEY EXCHANGE INITIALIZATION]")
            print("[Step 1: Receiving Server's Public Keys]\n")
            
            # Pret mesazhin e par nga serveri
            message = await websocket.recv()
            data = json.loads(message)
            if data['type'] == 'init':
                # Ketu behet shnderrimi i celsav nga formati tekst ne objekte kriptografike qe kupton libraria
                self.server_rsa_public_key = CryptoUtils.deserialize_public_key(data['rsa_public_key'])
                server_ecdh_public_key = CryptoUtils.deserialize_ecdh_public_key(data['ecdh_public_key'])
                
                print(f"SERVER RSA PUBLIC KEY (2048-bit for Digital Signatures):\n{data['rsa_public_key']}")
                print(f"\nSERVER ECDH PUBLIC KEY (P-256 Elliptic Curve for Key Exchange):\n{data['ecdh_public_key']}\n")

                # Klienti gjeneron ciftin e vet t celsave per Diffie-Hellman
                print("[Step 2: Client Generating ECDH Keypair]\n")
                self.ecdh_private_key = CryptoUtils.generate_ecdh_keypair()
                self.ecdh_public_key = self.ecdh_private_key.public_key()
                print(f"CLIENT ECDH PRIVATE KEY (P-256): Generated and kept secret")
                print(f"CLIENT ECDH PUBLIC KEY (P-256): Generated\n")

                # "Paketimi" dhe dergimi i celsit publik te klientit tek serveri
                print("[Step 3: Client Sending ECDH Public Key to Server]\n")
                ecdh_public_pem = CryptoUtils.serialize_ecdh_public_key(self.ecdh_public_key)
                print(f"CLIENT ECDH PUBLIC KEY SENT (P-256):\n{ecdh_public_pem}\n")
                await websocket.send(json.dumps({
                    'type': 'ecdh_exchange',
                    'ecdh_public_key': ecdh_public_pem
                }))

                # FAZA 2: SHARED SECRET ESTABLISHMENT (Diffie-Hellman)
                print("\n[PHASE 2: SHARED SECRET ESTABLISHMENT]")
                print("[Step 4: Client Deriving Shared Secret]")
                print("✓ [Requirement: Diffie-Hellman] Computing shared secret using client private key + server public key\n")

                # Celsi privat i klientit + Celsi publik i serverit = Shared Secret
                self.shared_key = CryptoUtils.generate_shared_secret(self.ecdh_private_key, server_ecdh_public_key)
                shared_key_hex = self.shared_key.hex()
                print(f"Shared Secret Successfully Derived (hex):")
                print(f"{shared_key_hex}\n")

                # FAZA 3: AUTHENTICATION, INTEGRITY & NON-REPUDIATION
                print("\n[PHASE 3: MESSAGE INTEGRITY & AUTHENTICATION]")
                print("[Step 5: Receiving Server's Signed Welcome Message]")
                print("✓ [Requirement: Digital Signatures] Receiving encrypted + signed message from server\n")

                # Pranon mesazhin e "mireseardhjes" qe vjen i enkriptuar dhe i nenshkruar nga serveri
                message = await websocket.recv()
                data = json.loads(message)
                if data['type'] == 'welcome':
                    encrypted_msg = data['message'] # Teksti i koduar (Ciphertext)
                    signature = data['signature']  # Nenshkrimi dixhital RSA i serverit
                    print(f"Encrypted Message: {encrypted_msg[:80]}...")
                    print(f"RSA Signature: {signature[:80]}...\n")
                    
                    print("[Step 6: Decrypting and Verifying Message]")
                    print("✓ [Requirement: AES Encryption] Decrypting with shared secret key")
                    print("✓ [Requirement: Digital Signatures] Verifying RSA-PSS signature with server public key")
                    print("✓ [Requirement: Message Integrity] Verifying message digest (SHA-256)\n")
                    
                    # 1. Dekripton mesazhin duke perdorur AES dhe celsin e perbashket 
                    decrypted_msg = CryptoUtils.decrypt_message(encrypted_msg, self.shared_key)
                    print(f"Decrypted Message: {decrypted_msg}")

                    # 2. Verifikon nenshkrimin duke perdorur celsin publik RSA te serverit (Integriteti dhe Autentikimi)
                    # Ky hap verteton qe mesazhi erdhi vertet nga serveri dhe nuk eshte modifikuar
                    if CryptoUtils.verify_signature(decrypted_msg, signature, self.server_rsa_public_key):
                        print("✓ Signature verified successfully")
                        print("✓ Server authentication confirmed (Non-Repudiation)")
                        print("✓ Secure communication established\n")
                        print("="*80 + "\n")
                    else:
                        print("✗ Signature verification failed!")
                        return

            # Nese faza e mbrojtjes kalon me sukses tash hapet nderfaqja e konsoles per bisede
            await self.console_interface(websocket)

# FAZA 4: ENCRYPTED COMMUNICATION (Komunikimi i dyanshëm)
    async def console_interface(self, websocket):

        # Nenfunksion asinkron qe qendron ne sfond dhe degjon per mesazhe te reja nga serveri
        async def receive_messages():
            try:
                async for message in websocket:
                    data = json.loads(message)
                    if data['type'] == 'message':
                        encrypted_msg = data['message']
                        signature = data['signature']
                        print(f"\n[Message Received from Server]")
                        print(f"Encrypted (Base64): {encrypted_msg[:80]}...")
                        print(f"Signature (RSA-PSS): {signature[:80]}...")
                        print(f"\n✓ [Requirement: Encrypted Communication] Decrypting with AES shared secret")
                        print(f"✓ [Requirement: Digital Signatures] Verifying RSA-PSS signature")
                        print(f"✓ [Requirement: Message Integrity] Checking SHA-256 digest\n")

                        # Cdo mesazh i ri dekriptohet
                        decrypted_msg = CryptoUtils.decrypt_message(encrypted_msg, self.shared_key)
                        print(f"Decrypted Message: {decrypted_msg}")
                        
                        # ...dhe i verifikohet nenshkrimi per te garantuar mos-mohimin
                        if CryptoUtils.verify_signature(decrypted_msg, signature, self.server_rsa_public_key):
                            print("✓ Signature verified - Message authenticated (Non-Repudiation confirmed)")
                        else:
                            print("✗ Invalid signature - Message rejected!")
            except:
                pass

        receive_task = asyncio.create_task(receive_messages())

# Cikli kryesor qe pret shkrimin e mesazheve nga perdoruesi ne konsole
        while True:
            # Merr inputin nga tastiera pa bllokuar proceset e tjera asinkrone
            command = await asyncio.get_event_loop().run_in_executor(None, input, "\n[Send Message] Client> ")
            if command == "quit":
                print("\n✓ Closing secure connection...")
                break
            elif command:
                print(f"\n[ENCRYPTED COMMUNICATION PHASE]")
                print(f"Original Message: {command}")
                print(f"✓ [Requirement: Encrypted Communication] Encrypting with AES using shared secret\n")

                # Enkripton mesazhin e shkruar me AES-CBC duke perdorur celsin e perbashket 
                encrypted = CryptoUtils.encrypt_message(command, self.shared_key)
                print(f"Encrypted (Base64): {encrypted[:80]}...")
                print(f"✓ Message Sent\n")

                # Dergon mesazhin e enkriptuar ne format JSON tek serveri
                await websocket.send(json.dumps({
                    'type': 'message',
                    'message': encrypted
                }))

        receive_task.cancel() # Anulon degjuesin nese perdoruesi shkruan 'quit'

# Ketu bohet nisja e programit (Main Entry Point dmth)
async def main():
    print("\n" + "="*80)
    print("REQUIREMENT VERIFICATION CHECKLIST")
    print("="*80)
    print("✓ [Requirement 1] Console Application - Client running in console mode")
    print("✓ [Requirement 2] Connecting to server for secure communication")
    print("="*80)
    
    client = SecureClient()
    await client.connect() # Nis ekzekutimi i klientit

if __name__ == "__main__":
    asyncio.run(main()) # Nis rrjedhen e asyncio event loop
