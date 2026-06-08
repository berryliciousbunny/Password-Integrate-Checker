# hibp_check.py
import hashlib
import requests

HIBP_RANGE_URL = 'https://api.pwnedpasswords.com/range/'

def sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode('utf-8')).hexdigest().upper()


def check_pwned(password: str) -> int:
    """Returns count of occurrences found in HIBP database. 0 => not found.
    Uses k-anonymity: sends first 5 hex chars of SHA-1 hash.
    """
    h = sha1_hex(password)
    prefix, suffix = h[:5], h[5:]
    res = requests.get(HIBP_RANGE_URL + prefix)
    if res.status_code != 200:
        raise RuntimeError('HIBP request failed with ' + str(res.status_code))
    # response lines like: SFX:COUNT
    for line in res.text.splitlines():
        sfx, count = line.split(':')
        if sfx == suffix:
            return int(count)
    return 0
