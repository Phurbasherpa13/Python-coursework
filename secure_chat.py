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

try:
    import nest_asyncio
    nest_asyncio.apply()
except ImportError:
    pass # We will handle this in requirements if needed

