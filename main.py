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

    def setup_ui(self):
        # Основной контейнер
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)

        #ВВОД ТЕКСТА
        input_frame = ttk.LabelFrame(main_frame, text="Исходный текст", padding="10")
        input_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(0, weight=1)
        
        self.input_text = scrolledtext.ScrolledText(input_frame, width=80, height=8, font=('Courier', 10))
        self.input_text.grid(row=0, column=0, sticky=(tk.W, tk.E))

        #СЕКЦИЯ КЛЮЧА
        key_frame = ttk.LabelFrame(main_frame, text="Ключ шифрования", padding="10")
        key_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Первая строка: поле ввода и кнопка показа/скрытия
        key_input_frame = ttk.Frame(key_frame)
        key_input_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))
        key_input_frame.columnconfigure(1, weight=1)
        
        ttk.Label(key_input_frame, text="Ключ:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.key_entry = ttk.Entry(key_input_frame, width=60, show="*", font=('Courier', 10))
        self.key_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))

        self.show_key_var = tk.BooleanVar(value=False)
        self.show_key_btn = ttk.Checkbutton(
            key_input_frame, 
            text="Показать ключ", 
            variable=self.show_key_var,
            command=self.toggle_key_visibility
        )
        self.show_key_btn.grid(row=0, column=2)
        
        # Вторая строка: динамическая индикация безопасности
        self.key_security_frame = ttk.Frame(key_frame)
        self.key_security_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Полоса прогресса (визуализация силы ключа)
        self.key_progress = ttk.Progressbar(
            self.key_security_frame, 
            length=300,
            mode='determinate'
        )
        self.key_progress.grid(row=0, column=0, sticky=tk.W, padx=(0, 10))

         # Метка с оценкой ключа
        self.key_status_label = ttk.Label(
            self.key_security_frame, 
            text="Введите ключ",
            font=('Arial', 9)
        )
        self.key_status_label.grid(row=0, column=1, sticky=tk.W)

         #СЕКЦИЯ КНОПОК
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=15)
        
        # Кнопки основного функционала
        self.encrypt_btn = ttk.Button(
            button_frame, 
            text="🔒 Зашифровать", 
            command=self.encrypt_text,
            width=20
        )
        self.encrypt_btn.pack(side=tk.LEFT, padx=10)
        
        self.decrypt_btn = ttk.Button(
            button_frame, 
            text="🔓 Расшифровать", 
            command=self.decrypt_text,
            width=20
        )
        self.decrypt_btn.pack(side=tk.LEFT, padx=10)
        
        self.clear_btn = ttk.Button(
            button_frame, 
            text="🗑️ Очистить всё", 
            command=self.clear_all,
            width=20
        )
        self.clear_btn.pack(side=tk.LEFT, padx=10)

         #СЕКЦИЯ РЕЗУЛЬТАТА
        result_frame = ttk.LabelFrame(main_frame, text="Результат", padding="10")
        result_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        
        # Поле для отображения результата
        self.result_text = scrolledtext.ScrolledText(
            result_frame, 
            width=80, 
            height=8,
            font=('Courier', 10),
            wrap=tk.WORD
        )
        self.result_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Метка статуса операции
        self.operation_label = ttk.Label(
            result_frame,
            text="Ожидание операции...",
            font=('Arial', 9, 'italic')
        )
        self.operation_label.grid(row=1, column=0, sticky=tk.W, pady=(5, 0))

        #СЕКЦИЯ ТРЕБОВАНИЙ
        requirements_frame = ttk.LabelFrame(main_frame, text="Требования к ключу", padding="10")
        requirements_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 5))
        
        requirements_text = SimpleKeyValidator.get_key_requirements()
        self.requirements_label = ttk.Label(
            requirements_frame, 
            text=requirements_text,
            justify=tk.LEFT
        )
        self.requirements_label.pack()

                #СТАТУС БАР
        self.status_bar = ttk.Label(
            self.root, 
            text="Готов к работе. Введите текст и ключ.", 
            relief=tk.SUNKEN,
            padding=5
        )
        self.status_bar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        
        
     