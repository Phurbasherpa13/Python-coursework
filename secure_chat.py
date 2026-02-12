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

        self.create_widgets()
        self.core.start_thread()
        
        # Load previous chat history on startup
        self.load_history()
        
        # Handle window close event to ensure everything is saved (though we save instantly)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_widgets(self):
        # Header
        ttk.Label(self.root, text=">> SECURE WEBSOCKET CHAT <<", font=("Consolas", 16, "bold")).pack(pady=10)

        # Config
        config_frame = ttk.Frame(self.root)
        config_frame.pack(fill="x", padx=20)
        
        ttk.Label(config_frame, text="IP:").grid(row=0, column=0)
        self.ip_entry = ttk.Entry(config_frame, width=15)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, padx=5)

        ttk.Label(config_frame, text="Port:").grid(row=0, column=2)
        self.port_entry = ttk.Entry(config_frame, width=8)
        self.port_entry.insert(0, "8765")
        self.port_entry.grid(row=0, column=3, padx=5)

        ttk.Label(config_frame, text="Key:").grid(row=1, column=0, pady=5)
        self.key_entry = ttk.Entry(config_frame, show="*", width=20)
        self.key_entry.insert(0, "MySecretKey")
        self.key_entry.grid(row=1, column=1, columnspan=3, pady=5)

        # Buttons
        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(pady=10)
        
        self.host_btn = ttk.Button(btn_frame, text="HOST (Server)", command=self.start_host)
        self.host_btn.pack(side="left", padx=5)
        
        self.conn_btn = ttk.Button(btn_frame, text="JOIN (Client)", command=self.start_client)
        self.conn_btn.pack(side="left", padx=5)

        # Chat Display
        self.chat_log = scrolledtext.ScrolledText(self.root, bg="black", fg="#00ff00", font=("Consolas", 10), state="disabled")
        self.chat_log.pack(fill="both", expand=True, padx=20)

        # Input
        input_frame = ttk.Frame(self.root)
        input_frame.pack(fill="x", padx=20, pady=10)
        self.msg_entry = ttk.Entry(input_frame, font=("Consolas", 10))
        self.msg_entry.pack(side="left", fill="x", expand=True)
        self.msg_entry.bind("<Return>", lambda e: self.send())
        self.send_btn = ttk.Button(input_frame, text="SEND", command=self.send, state="disabled")
        self.send_btn.pack(side="right", padx=5)

    # --- New Persistence Functions ---

    def save_to_file(self, message):
        """Saves the log message to a text file with a timestamp."""
        try:
            timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"{timestamp} {message}\n")
        except Exception as e:
            print(f"Error saving log: {e}")

    def load_history(self):
        """Reads the log file and displays past messages."""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    history = f.read()
                    if history:
                        self.chat_log.config(state="normal")
                        self.chat_log.insert(tk.END, history)
                        self.chat_log.see(tk.END)
                        self.chat_log.config(state="disabled")
            except Exception as e:
                print(f"Error loading history: {e}")

    def on_close(self):
        """Safely disconnect and close."""
        self.core.stop()
        self.root.destroy()

    # --- Existing Networking Logic ---

    def start_host(self):
        if not self.check_inputs(): return
        asyncio.run_coroutine_threadsafe(
            self.core.host_server(self.ip_entry.get(), int(self.port_entry.get())),
            self.core.loop
        )
        self.toggle_inputs(False)

    def start_client(self):
        if not self.check_inputs(): return
        uri = f"ws://{self.ip_entry.get()}:{self.port_entry.get()}"
        asyncio.run_coroutine_threadsafe(
            self.core.connect_client(uri),
            self.core.loop
        )
        self.toggle_inputs(False)

    def check_inputs(self):
        if not self.key_entry.get():
            messagebox.showerror("Error", "Encryption Key required")
            return False
        self.core.set_security(self.key_entry.get())
        return True

    def toggle_inputs(self, enable):
        state = "normal" if enable else "disabled"
        self.host_btn.config(state=state)
        self.conn_btn.config(state=state)
        self.send_btn.config(state=state if not enable else "disabled") # Invert logic for send button
        self.ip_entry.config(state=state)
        self.port_entry.config(state=state)
        self.key_entry.config(state=state)

    def send(self):
        msg = self.msg_entry.get()
        if msg:
            self.core.send(msg)
            # We pass 'True' to indicate this is a 'Sent' message for the logger
            self.log_to_chat(f"[You] {msg}")
            self.msg_entry.delete(0, tk.END)

    def on_connected(self, msg):
        self.log_to_chat(f"[SYSTEM] {msg}")
        self.send_btn.config(state="normal")

    def on_disconnected(self):
        self.log_to_chat("[SYSTEM] Disconnected")
        self.toggle_inputs(True)
        self.send_btn.config(state="disabled")

    def log_to_chat(self, msg):
        # 1. Save to file immediately (Persistence)
        self.save_to_file(msg)
        
        # 2. Update GUI (Standard Tkinter thread update)
        def update():
            self.chat_log.config(state="normal")
            self.chat_log.insert(tk.END, msg + "\n")
            self.chat_log.see(tk.END)
            self.chat_log.config(state="disabled")
        self.root.after(0, update)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatApp(root)
    root.mainloop()
    