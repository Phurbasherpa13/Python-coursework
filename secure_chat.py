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

    def send(self, message):
        """Sends message via asyncio from the GUI thread."""
        if not self.websocket or not self.security:
            return
        
        encrypted = self.security.encrypt_message(message)
        
        # Schedule the send coroutine in the async loop
        asyncio.run_coroutine_threadsafe(self.websocket.send(encrypted), self.loop)

    def stop(self):
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        self.running = False


class SecureChatApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure WebSocket Chat")
        self.root.geometry("600x700")
        self.root.configure(bg="#1e1e1e")

        # File for saving history
        self.log_file = "chat_history.txt"

        # Styling
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure("TFrame", background="#1e1e1e")
        self.style.configure("TLabel", background="#1e1e1e", foreground="#00ff00", font=("Consolas", 10))
        self.style.configure("TButton", font=("Consolas", 10, "bold"), background="#00cc00")
        self.style.map("TButton", background=[("active", "#00ff00")])

        # Core Logic
        self.core = ChatCore(
            log_callback=self.log_to_chat,
            connected_callback=self.on_connected,
            disconnected_callback=self.on_disconnected
        )



if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()
    