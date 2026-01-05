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
        """
        Простая проверка ключа.
        
        Returns:
            tuple: (is_valid, error_message, score)
        """
        if not key:
            return False, "Ключ не может быть пустым", 0
        
        score = 0
        max_score = 100
        
        # 1. Проверка длины (0-30 баллов)
        if len(key) >= 12:
            score += 30
        elif len(key) >= 8:
            score += 20