# cli.py
import argparse
from password_checker.storage import init_db, add_user, find_user
from password_checker.crypto import hash_password, verify_password


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default='sqlite:///passwords.db')
    sub = parser.add_subparsers(dest='cmd')

    add = sub.add_parser('add')
    add.add_argument('username')
    add.add_argument('password')

    verify = sub.add_parser('verify')
    verify.add_argument('username')
    verify.add_argument('password')

    args = parser.parse_args()
    Session = init_db(args.db)

    if args.cmd == 'add':
        ph = hash_password(args.password)
        add_user(Session, args.username, ph, note=args.password)  # demo: store plaintext in note -> don't do this in real apps
        print('User added')
    elif args.cmd == 'verify':
        u = find_user(Session, args.username)
        if not u:
            print('No such user')
            return
        ok = verify_password(u.password_hash, args.password)
        print('OK' if ok else 'INVALID')
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
