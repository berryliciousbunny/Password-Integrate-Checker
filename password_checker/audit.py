# audit.py
from storage import init_db, get_all_users
from hibp_check import check_pwned
from check_strength import score_password, meets_policy
from crypto import verify_password

def classify_severity(policy_ok, pwned_count):
    if pwned_count and pwned_count > 0:
        return 'HIGH'
    if policy_ok is False:
        return 'MED'
    if policy_ok is True:
        return 'LOW'
    return 'INFO'

def run_audit(db_path='sqlite:///passwords.db'):
    Session = init_db(db_path)
    users = get_all_users(Session)
    report = []
    for u in users:
        entry = {'username': u.username}
        # Can't reverse the password from hash, so audit relies on either
        # - plaintext import (dangerous), or
        # - stored 'note' containing last-changed indicator; for demo we'll
        #   assume the DB was populated via our CLI and we keep plain 'candidate' temporarily
        # In many real audits you only discover weak passwords when users reset them or you push a policy.
        # Here we'll only score if we have plaintext in note (DEMO ONLY)
        candidate = u.note or None
        if candidate:
            entry['strength'] = score_password(candidate)
            entry['policy_ok'], entry['issues'] = meets_policy(candidate)
            entry['pwned_count'] = check_pwned(candidate)

            entry['severity'] = classify_severity(
                entry['policy_ok'],
                entry['pwned_count']
            )
        else:
            entry['strength'] = None
            entry['policy_ok'] = None
            entry['pwned_count'] = None
            entry['severity'] = 'INFO'
        report.append(entry)
    return report
