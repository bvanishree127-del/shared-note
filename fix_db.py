import sqlite3
conn = sqlite3.connect('secrets.db')
cursor = conn.cursor()
cursor.execute("PRAGMA table_info(secrets)")
cols = [c[1] for c in cursor.fetchall()]
if 'text_ciphertext' not in cols:
    cursor.execute("ALTER TABLE secrets ADD COLUMN text_ciphertext TEXT")
    print("✅ Column added.")
else:
    print("ℹ️ Column already exists.")
conn.commit()
conn.close()