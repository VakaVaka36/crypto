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
        elif len(key) >= 6:
            score += 10
        else:
            return False, f"Ключ должен быть не менее {SimpleKeyValidator.MIN_LENGTH} символов", score
        
        # 2. Проверка на простые пароли
        if key.lower() in SimpleKeyValidator.COMMON_PASSWORDS:
            return False, "Ключ слишком простой (в списке распространенных паролей)", 0
        
        # 3. Проверка наличия заглавной буквы (15 баллов)
        if re.search(r'[A-ZА-Я]', key):
            score += 15
        
        # 4. Проверка наличия цифры (15 баллов)
        if re.search(r'\d', key):
            score += 15
        
        # 5. Проверка наличия специальных символов (20 баллов)
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', key):
            score += 20

        # 6. Проверка на однотипность
        if key.isdigit():
            return False, "Ключ не должен состоять только из цифр", score
        if key.isalpha():
            return False, "Ключ не должен состоять только из букв", score
