# crypto.py
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import bcrypt

# Use Argon2id via argon2-cffi
_ph = PasswordHasher(
    time_cost=2,      # iterations (tune)
    memory_cost=2 ** 16,  # 65536 KiB = 64 MiB memory
    parallelism=2,
)

FALLBACK = 'bcrypt'

def hash_password(password: str) -> str:
    """Return a string containing algorithm-tagged hash. We'll use 'argon2$...' or 'bcrypt$...'."""
    try:
        a = _ph.hash(password)
        return f"argon2${a}"
    except Exception:
        # fallback to bcrypt
        salt = bcrypt.gensalt(rounds=12)
        h = bcrypt.hashpw(password.encode('utf-8'), salt)
        return f"bcrypt${h.decode()}"


def verify_password(stored: str, password: str) -> bool:
    """Verify a password against a stored hash. Stored string is prefixed with algorithm name."""
    if stored.startswith('argon2$'):
        enc = stored.split('argon2$', 1)[1]
        try:
            return _ph.verify(enc, password)
        except VerifyMismatchError:
            return False
    elif stored.startswith('bcrypt$'):
        enc = stored.split('bcrypt$', 1)[1].encode('utf-8')
        return bcrypt.checkpw(password.encode('utf-8'), enc)
    else:
        raise ValueError('Unknown hash algorithm')
