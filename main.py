import hashlib
import struct
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import binascii
import re
from typing import Tuple

# Определяем SimpleKeyValidator ПЕРЕД его использованием
class SimpleKeyValidator:
    """
    Простой валидатор ключа с минимальными требованиями.
    """
    
    MIN_LENGTH = 8
    COMMON_PASSWORDS = {
        'password', '123456', 'qwerty', 'admin', 'welcome',
        'password1', '12345678', 'abc123', '111111', 'letmein',
        'qwerty123', 'admin123', '123123', '123456789', '1234567890'
    }
    
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
        """Возвращает требования к ключу в текстовом виде."""
        return (
            f"Требования к ключу:\n"
            f"✓ Не менее {SimpleKeyValidator.MIN_LENGTH} символов\n"
            f"✓ Хотя бы одна заглавная буква\n"
            f"✓ Хотя бы одна цифра\n"
            f"✓ Не использовать простые пароли\n"
            f"✓ Смешивать разные типы символов"
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
        self.root.title("Криптографический модуль с динамической проверкой ключа")
        self.root.geometry("850x750")
        
        # Настраиваем цвета для разных уровней безопасности
        self.colors = {
            'weak': '#ff6b6b',      # Красный
            'medium': '#ffd93d',    # Желтый
            'strong': '#6bcf7f',    # Зеленый
            'excellent': '#4d96ff', # Синий
            'default': '#cccccc'    # Серый
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
        
        # Загрузка тестовых данных
        self.load_test_data()
    
    def toggle_key_visibility(self):
        """Переключение видимости ключа"""
        if self.show_key_var.get():
            self.key_entry.config(show="")
        else:
            self.key_entry.config(show="*")
    
    def on_key_changed(self, event=None):
        """Динамическая проверка ключа при изменении"""
        key = self.key_entry.get().strip()
        
        if not key:
            # Сброс индикаторов при пустом ключе
            self.key_progress['value'] = 0
            self.key_status_label.config(
                text="Введите ключ",
                foreground='gray'
            )
            return
        
        # Проверяем ключ
        is_valid, message, score = self.crypto.key_validator.validate_key(key)
        
        # Обновляем полосу прогресса
        self.key_progress['value'] = score
        
        # Определяем цвет и текст в зависимости от силы ключа
        if not is_valid:
            # Ключ не соответствует минимальным требованиям
            self.key_status_label.config(
                text=f"❌ {message}",
                foreground='red'
            )
        else:
            # Ключ соответствует требованиям, показываем силу
            if score >= 80:
                color = self.colors['excellent']
                emoji = "⭐⭐⭐⭐⭐"
            elif score >= 60:
                color = self.colors['strong']
                emoji = "⭐⭐⭐⭐"
            elif score >= 40:
                color = self.colors['medium']
                emoji = "⭐⭐⭐"
            else:
                color = self.colors['weak']
                emoji = "⭐⭐"
            
            self.key_status_label.config(
                text=f"{emoji} {message}",
                foreground=color
            )
    
    def check_if_encryption_needed(self) -> Tuple[bool, str]:
        """
        Проверяет, нужно ли выполнять шифрование или данные уже зашифрованы.
        
        Returns:
            Tuple[bool, str]: (нужно_шифровать, сообщение)
        """
        current_key = self.key_entry.get().strip()
        source_text = self.input_text.get("1.0", tk.END).strip()
        result_text = self.result_text.get("1.0", tk.END).strip()
        
        # Проверка 1: Пустые поля
        if not source_text:
            return False, "Введите текст для шифрования в поле 'Исходный текст'."
        
        if not current_key:
            return False, "Введите ключ шифрования."
        
        # Проверка 2: Текст уже зашифрован (hex в результате)
        if result_text and self.crypto.is_hex_string(result_text):
            if self.last_operation == 'encrypt':
                # Проверяем, не тот же ли это текст и ключ
                if (source_text == self.last_source_text and 
                    current_key == self.last_key and
                    result_text == self.last_encrypted_text):
                    return False, "Текст уже зашифрован с этим ключом.\n\n" \
                                 "Если хотите зашифровать другой текст:\n" \
                                 "1. Измените исходный текст\n" \
                                 "2. Измените ключ\n" \
                                 "3. Нажмите 'Очистить всё' и введите новые данные"
        
        # Проверка 3: Тот же текст и ключ, что и в прошлый раз
        if (self.last_operation == 'encrypt' and 
            source_text == self.last_source_text and 
            current_key == self.last_key):
            return False, "Вы пытаетесь зашифровать тот же текст тем же ключом.\n\n" \
                         "Если хотите получить другой результат:\n" \
                         "1. Измените исходный текст\n" \
                         "2. Измените ключ шифрования"
        
        return True, "Шифрование может быть выполнено."
    
    def encrypt_text(self):
        """Шифрование текста"""
        try:
            # Проверяем, нужно ли выполнять шифрование
            need_encrypt, message = self.check_if_encryption_needed()
            
            if not need_encrypt:
                # Показываем диалоговое окно с информацией
                response = messagebox.askyesno(
                    "Повторное шифрование",
                    f"{message}\n\n"
                    "Вы уверены, что хотите выполнить шифрование?"
                )
                if not response:
                    return
            
            # Получаем текущие данные
            source_text = self.input_text.get("1.0", tk.END).strip()
            current_key = self.key_entry.get().strip()
            
            # Проверяем ключ перед операцией
            is_valid, error_msg, score = self.crypto.key_validator.validate_key(current_key)
            
            if not is_valid:
                # Ключ не соответствует минимальным требованиям
                response = messagebox.askyesno(
                    "Ошибка ключа",
                    f"{error_msg}\n\n"
                    "Ключ не соответствует минимальным требованиям безопасности.\n"
                    "Хотите продолжить с этим ключом?\n\n"
                    "⚠ ВНИМАНИЕ: Использование слабого ключа может привести\n"
                    "к компрометации зашифрованных данных!"
                )
                if not response:
                    return
            elif score < 40:  # Слабый, но допустимый ключ
                response = messagebox.askyesno(
                    "Слабый ключ",
                    f"Ключ имеет низкую оценку безопасности ({score}/100).\n"
                    "Рекомендуется использовать более сложный ключ.\n\n"
                    "Продолжить с текущим ключом?"
                )
                if not response:
                    return
            
            # Выполняем шифрование
            result = self.crypto.encrypt(source_text, current_key)
            
            # Сохраняем историю операций
            self.last_source_text = source_text
            self.last_key = current_key
            self.last_encrypted_text = result
            self.last_operation = 'encrypt'
            
            # Отображаем результат
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", result)
            
            # Обновляем метку операции
            self.operation_label.config(
                text="🔒 Текст успешно зашифрован",
                foreground='green'
            )
            
            # Обновляем статус бар
            self.status_bar.config(
                text=f"Текст успешно зашифрован. Длина ключа: {len(current_key)} символов, оценка: {score}/100"
            )
            
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при шифровании: {str(e)}")
            self.operation_label.config(
                text=f"❌ Ошибка при шифровании",
                foreground='red'
            )
    
    def decrypt_text(self):
        """Дешифрование текста"""
        try:
            current_key = self.key_entry.get().strip()
            
            if not current_key:
                messagebox.showwarning("Внимание", "Введите ключ шифрования")
                return
            
            # Определяем, какой текст дешифровать
            result_text = self.result_text.get("1.0", tk.END).strip()
            
            if not result_text:
                messagebox.showwarning("Внимание", 
                    "Нет данных для дешифрования.\n"
                    "Сначала зашифруйте текст или введите hex-данные в поле 'Результат'.")
                return
            
            
            # Проверка 2: Текст не является hex-строкой
            if not self.crypto.is_hex_string(result_text):
                # Если не hex, проверяем, не является ли это уже дешифрованным текстом
                if self.last_operation == 'decrypt':
                    messagebox.showinfo("Информация", 
                        "Текст уже расшифрован.\n"
                        "Для повторного шифрования используйте кнопку 'Зашифровать'.")
                    return
                else:
                    # Пытаемся дешифровать последний зашифрованный текст
                    if self.last_encrypted_text:
                        text_to_decrypt = self.last_encrypted_text
                    else:
                        messagebox.showerror("Ошибка",
                            "Текст в поле 'Результат' не является hex-данными.\n"
                            "Убедитесь, что это зашифрованный текст в hex-формате.")
                        return
            else:
                text_to_decrypt = result_text
            
            # Проверяем ключ перед операцией
            is_valid, error_msg, score = self.crypto.key_validator.validate_key(current_key)
            
            if not is_valid:
                response = messagebox.askyesno(
                    "Ошибка ключа",
                    f"{error_msg}\n\nПродолжить с этим ключом?"
                )
                if not response:
                    return
            
            # Выполняем дешифрование
            result = self.crypto.decrypt(text_to_decrypt, current_key)
            
            # Сохраняем историю операций
            self.last_decrypted_text = result
            self.last_key = current_key
            self.last_operation = 'decrypt'
            
            # Отображаем результат
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", result)
            
            # Обновляем метку операции
            self.operation_label.config(
                text="🔓 Текст успешно расшифрован",
                foreground='green'
            )
            
            # Обновляем статус бар
            self.status_bar.config(
                text=f"Текст успешно расшифрован. Использован ключ длиной {len(current_key)} символов"
            )
            
        except binascii.Error:
            messagebox.showerror(
                "Ошибка формата",
                "Неверный формат зашифрованного текста.\n"
                "Убедитесь, что вводите корректные hex-данные для дешифрования."
            )
            self.operation_label.config(
                text="❌ Ошибка: неверный формат данных",
                foreground='red'
            )
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при дешифровании: {str(e)}")
            self.operation_label.config(
                text=f"❌ Ошибка при дешифровании",
                foreground='red'
            )
    
    def clear_all(self):
        """Очистка всех полей и сброс состояния"""
        # Очищаем текстовые поля
        self.input_text.delete("1.0", tk.END)
        self.result_text.delete("1.0", tk.END)
        self.key_entry.delete(0, tk.END)
        
        # Сбрасываем индикаторы
        self.key_progress['value'] = 0
        self.key_status_label.config(
            text="Введите ключ",
            foreground='gray'
        )
        
        # Сбрасываем переключатель видимости
        self.show_key_var.set(False)
        self.key_entry.config(show="*")
        
        # Сбрасываем метки
        self.operation_label.config(
            text="Ожидание операции...",
            foreground='gray'
        )
        
        # Сбрасываем историю операций
        self.last_operation = None
        self.last_encrypted_text = ""
        self.last_decrypted_text = ""
        self.last_source_text = ""
        self.last_key = ""
        
        # Обновляем статус бар
        self.status_bar.config(text="Все поля очищены. Готов к работе.")
    
    def load_test_data(self):
        """Загрузка тестовых данных"""
        test_data = """Конфиденциальная информация компании "ТехноПрогресс":

1. Финансовый отчет за Q1 2024:
   - Выручка: $1,250,000
   - Чистая прибыль: $315,000
   - Рост: 15.2% к прошлому году

2. Новые проекты:
   - Проект "Альфа": разработка ИИ-ассистента
   - Проект "Бета": облачное хранилище
   - Проект "Гамма": IoT-платформа"""
        
        self.input_text.insert("1.0", test_data)
        self.key_entry.insert(0, "SecureKey2024!")
        
        # Запускаем начальную проверку ключа
        self.on_key_changed()


def main():
    """Главная функция запуска приложения"""
    root = tk.Tk()
    app = UnifiedCryptoApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()