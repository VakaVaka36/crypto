import hashlib
import struct
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import binascii
import re
from typing import Tuple

class SimpleKeyValidator:
    MIN_LENGTH = 8
    COMMON_PASSWORDS = {'password', '123456', 'qwerty', 'admin'}
    
    @staticmethod
    def validate_key(key: str) -> tuple:
        if not key:
            return False, 'Ключ не может быть пустым', 0
        if len(key) < SimpleKeyValidator.MIN_LENGTH:
            return False, f'Ключ должен быть не менее {MIN_LENGTH} символов', 0