import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).with_name("secrets_app.db")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: py make_admin.py you@example.com")
        raise SystemExit(1)

    email = sys.argv[1].strip().lower()

    if not DB_PATH.exists():
        print(f"ERROR: DB not found: {DB_PATH}")
        raise SystemExit(1)

    conn = sqlite3.connect(str(DB_PATH))
    cur = conn.cursor()

    cur.execute("SELECT id, email, is_admin, is_vip FROM user WHERE lower(email)=?", (email,))
    row = cur.fetchone()

    if not row:
        print("ERROR: No such user in DB.")
        print("First: open the app → Account → Register, then run this script again.")
        raise SystemExit(1)

    user_id, email_db, is_admin, is_vip = row

    cur.execute(
        "UPDATE user SET is_admin=1, is_vip=1 WHERE id=?",
        (user_id,),
    )
    conn.commit()
    conn.close()

    print("OK")
    print(f"User: {email_db}")
    print("is_admin: 1")
    print("is_vip:   1")


if __name__ == "__main__":
    main()
