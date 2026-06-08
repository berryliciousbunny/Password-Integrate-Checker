# tests/test_crypto.py
from password_checker.crypto import hash_password, verify_password


def test_hash_and_verify():
    pwd = 'CorrectHorseBatteryStaple!234'
    h = hash_password(pwd)
    assert verify_password(h, pwd) is True
    assert verify_password(h, 'wrongpassword') is False
