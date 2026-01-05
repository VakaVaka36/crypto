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
    
    def _sha1_padding(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        orig_len = len(message) * 8
        message += b'\x80'
        
        while (len(message) * 8) % 512 != 448:
            message += b'\x00'
        
        message += struct.pack('>Q', orig_len)
        return message
    
    def sha1_hash(self, message):
        message = self._sha1_padding(message)
        h0, h1, h2, h3, h4 = self.iv
        
        for i in range(0, len(message), 64):
            block = message[i:i+64]
            words = list(struct.unpack('>16I', block))
            
            for j in range(16, 80):
                word = (words[j-3] ^ words[j-8] ^ words[j-14] ^ words[j-16])
                words.append(self._left_rotate(word, 1))

            a, b, c, d, e = h0, h1, h2, h3, h4
            
            for j in range(80):
                if 0 <= j <= 19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= j <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= j <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6
                
                    temp = (self._left_rotate(a, 5) + f + e + k + words[j]) & 0xffffffff
                    e = d
                    d = c
                    c = self._left_rotate(b, 30)
                    b = a
                    a = temp

                h0 = (h0 + a) & 0xffffffff
                h1 = (h1 + b) & 0xffffffff
                h2 = (h2 + c) & 0xffffffff
                h3 = (h3 + d) & 0xffffffff
                h4 = (h4 + e) & 0xffffffff

            return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)
        
    def encrypt(self, text: str, key: str) -> str:
        """Шифрование текста"""
        key_hash = self.sha1_hash(key)
        text_bytes = text.encode('utf-8')
        key_bytes = bytes.fromhex(key_hash)
        
        encrypted = bytearray()
        for i, byte in enumerate(text_bytes):
            key_byte = key_bytes[i % len(key_bytes)]
            encrypted.append(byte ^ key_byte)
        
        return binascii.hexlify(encrypted).decode('utf-8')
    
    def decrypt(self, encrypted_hex: str, key: str) -> str:
        """Дешифрование текста"""
        key_hash = self.sha1_hash(key)
        encrypted_bytes = binascii.unhexlify(encrypted_hex)
        key_bytes = bytes.fromhex(key_hash)
        
        decrypted = bytearray()
        for i, byte in enumerate(encrypted_bytes):
            key_byte = key_bytes[i % len(key_bytes)]
            decrypted.append(byte ^ key_byte)
        
        return decrypted.decode('utf-8')
    
    def is_hex_string(self, text: str) -> bool:
        """Проверка, является ли строка hex-представлением"""
        try:
            # Пробуем преобразовать строку из hex
            bytes.fromhex(text)
            return True
        except ValueError:
            return False
        
class UnifiedCryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Криптографический модуль")
        self.root.geometry("850x750")
        
        # Настраиваем цвета для разных уровней безопасности
        self.colors = {
            'weak': '#ff6b6b',
            'medium': '#ffd93d',
            'strong': '#6bcf7f',
            'excellent': '#4d96ff',
            'default': '#cccccc' 
        }
        
        self.crypto = SHA1Crypto()
        self.setup_ui()

        # Связываем проверку ключа с изменением текста
        self.key_entry.bind('<KeyRelease>', self.on_key_changed)
        
        # Флажок для отслеживания последней операции
        self.last_operation = None  # 'encrypt' или 'decrypt'
        self.last_encrypted_text = ""  # Сохраняем последний зашифрованный текст
        self.last_decrypted_text = ""  # Сохраняем последний расшифрованный текст
        self.last_source_text = ""  # Сохраняем последний исходный текст для шифрования
        self.last_key = ""  # Сохраняем последний использованный ключ
