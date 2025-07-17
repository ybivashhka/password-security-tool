import pytest
from src.password_analyzer import PasswordAnalyzer

@pytest.fixture
def analyzer():
    return PasswordAnalyzer()

def test_entropy(analyzer):
    assert analyzer.calculate_entropy("password") == pytest.approx(24.0, 0.1)  # Примерно для float

def test_is_weak(analyzer):
    assert analyzer.is_weak("pass") is True
    assert analyzer.is_weak("X7#kL9@pQ2!mR4$z") is False

def test_generate_secure(analyzer):
    pass_gen = analyzer.generate_secure_password(12)
    assert len(pass_gen) == 12
    assert analyzer.calculate_entropy(pass_gen) > 60

def test_hash(analyzer):
    hash1 = analyzer.hash_password("test")
    hash2 = analyzer.hash_password("test")
    assert hash1 != hash2  # Salt делает уникальным

def test_crack(analyzer):
    cracked, attempts = analyzer.simulate_crack("password")
    assert cracked is True
    assert attempts > 0