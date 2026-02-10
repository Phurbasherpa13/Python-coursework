import os
from datetime import datetime 
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import asyncio
import websockets
import threading
import hashlib
import base64
import nest_asyncio # Allows asyncio to run in a nested way (useful for Tkinter integration)
import os
from datetime import datetime
try:
    import nest_asyncio
    nest_asyncio.apply()
except ImportError:
    pass # We will handle this in requirements if needed

from cryptography.fernet import Fernet, InvalidToken


class SecurityEngine:
    """Handles Encryption/Decryption using Fernet (AES-128)."""
    def __init__(self, password):
        self.key = self._generate_key_from_password(password)
        self.cipher = Fernet(self.key)

    def _generate_key_from_password(self, password):
        digest = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(digest)

    def encrypt_message(self, message):
        return self.cipher.encrypt(message.encode('utf-8'))

    def decrypt_message(self, encrypted_bytes):
        try:
            return self.cipher.decrypt(encrypted_bytes).decode('utf-8')
        except InvalidToken:
            return "[Error: Decryption Failed]"


class ChatCore:
    def __init__(self, log_callback, connected_callback, disconnected_callback):
        self.log = log_callback
        self.on_connected = connected_callback
        self.on_disconnected = disconnected_callback
        self.websocket = None
        self.loop = None
        self.security = None
        self.running = False

    def set_security(self, password):
        self.security = SecurityEngine(password)

    def start_thread(self):
        """Starts the asyncio event loop in a separate thread."""
        self.running = True
        self.thread = threading.Thread(target=self.run_loop, daemon=True)
        self.thread.start()

    def run_loop(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    async def host_server(self, host, port):
        try:
            async with websockets.serve(self.handle_connection, host, port):
                self.log(f"[SYSTEM] WebSocket Server started on ws://{host}:{port}")
                # Keep server running indefinitely
                await asyncio.Future()
        except Exception as e:
            self.log(f"[Error] Server failed: {e}")
            self.on_disconnected()

    async def handle_connection(self, websocket):
        self.websocket = websocket
        self.on_connected("Client Connected")
        self.log("[SYSTEM] Secure WebSocket connection established.")
        
        try:
            async for message in websocket:
                decrypted = self.security.decrypt_message(message)
                self.log(f"[Friend] {decrypted}")
        except websockets.exceptions.ConnectionClosed:
            self.log("[SYSTEM] Connection closed.")
        except Exception as e:
            self.log(f"[Error] {e}")
        finally:
            self.on_disconnected()

    async def connect_client(self, uri):
        try:
            async with websockets.connect(uri) as websocket:
                self.websocket = websocket
                self.on_connected("Connected to Server")
                self.log(f"[SYSTEM] Connected to {uri}")
                
                async for message in websocket:
                    decrypted = self.security.decrypt_message(message)
                    self.log(f"[Friend] {decrypted}")
        except Exception as e:
            self.log(f"[Error] Connection failed: {e}")
            self.on_disconnected()

