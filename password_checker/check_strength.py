# check_strength.py
from zxcvbn import zxcvbn

MIN_SCORE = 3  # zxcvbn score 0-4; 3+ considered pretty good


def score_password(pwd: str) -> dict:
    """Return zxcvbn score and details alongside simple policy results."""
    r = zxcvbn(pwd)
    return {
        'score': r['score'],
        'guesses': r['guesses'],
        'feedback': r['feedback'],
        'crack_time_display': r['crack_times_display'],
        'length': len(pwd),
        'has_upper': any(c.isupper() for c in pwd),
        'has_lower': any(c.islower() for c in pwd),
        'has_digit': any(c.isdigit() for c in pwd),
        'has_symbol': any(not c.isalnum() for c in pwd),
    }


def meets_policy(pwd: str) -> (bool, list):
    issues = []
    if len(pwd) < 8:
        issues.append('length < 8')
    if sum(1 for _ in pwd) < 12 and len(pwd) < 12:
        issues.append('consider length >= 12')
    s = score_password(pwd)
    if s['score'] < MIN_SCORE:
        issues.append('zxcvbn score < ' + str(MIN_SCORE))
    return (len(issues) == 0, issues)
