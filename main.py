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

        # 7. Проверка на последовательности
        if re.search(r'(123|234|345|456|567|678|789|abc|bcd|cde|def|qwe|wer|ert)', key.lower()):
            score -= 10

        # Определяем уровень безопасности
        if score >= 80:
            return True, f"Отличный ключ ({score}/100)", score
        elif score >= 60:
            return True, f"Хороший ключ ({score}/100)", score
        elif score >= 40:
            return True, f"Средний ключ ({score}/100)", score
        else:
            return True, f"Слабый ключ ({score}/100)", score
        
    @staticmethod
    def get_key_requirements() -> str:
        return (
            f"Требования к ключу:\n"
            f"Не менее {SimpleKeyValidator.MIN_LENGTH} символов\n"
            f"Хотя бы одна заглавная буква\n"
            f"Хотя бы одна цифра\n"
            f"Не использовать простые пароли\n"
            f"Смешивать разные типы символов"
        )
    
class SHA1Crypto:
    def __init__(self):
        self.iv = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        ]
        self.key_validator = SimpleKeyValidator()
    
    def _left_rotate(self, n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff