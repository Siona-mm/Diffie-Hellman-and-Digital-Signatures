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
