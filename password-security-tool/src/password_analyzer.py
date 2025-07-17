import math
import string
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets
import os

class PasswordAnalyzer:
    """Класс для анализа силы пароля, генерации безопасных паролей и симуляции взлома.

    Strong sides: Использует энтропию Шеннона для оценки силы, PBKDF2 для демонстрации хэширования,
    проверку на common words. Ethical note: Только для образовательных целей.
    """

    COMMON_WORDS = {'password', '123456', 'qwerty', 'letmein', 'admin'}  # Расширь в реале

    def calculate_entropy(self, password: str) -> float:
        """Расчет энтропии Шеннона для оценки силы пароля."""
        char_set = set(password)
        charset_size = len(char_set)
        if charset_size == 0:
            return 0.0
        entropy = math.log2(charset_size) * len(password)
        return round(entropy, 2)

    def is_weak(self, password: str) -> bool:
        """Проверка, слабый ли пароль (common или низкая энтропия)."""
        if password.lower() in self.COMMON_WORDS or len(password) < 8:
            return True
        entropy = self.calculate_entropy(password)
        return entropy < 60  # Порог для 'medium' силы

    def generate_secure_password(self, length: int = 16) -> str:
        """Генерация безопасного случайного пароля с высокой энтропией."""
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(chars) for _ in range(length))

    def hash_password(self, password: str) -> bytes:
        """Демо безопасного хэширования с PBKDF2 (в проде используй argon2)."""
        backend = default_backend()
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=backend
        )
        return kdf.derive(password.encode())

    def simulate_crack(self, password: str, max_attempts: int = 1000) -> Tuple[bool, int]:
        """Симуляция dictionary/brute-force взлома (ограничено для демо)."""
        attempts = 0
        for guess in self.COMMON_WORDS:
            attempts += 1
            if guess == password.lower():
                return True, attempts
            if attempts >= max_attempts:
                break
        # Stub для brute-force (не реальный для perf)
        return False, attempts