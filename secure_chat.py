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

