import sqlite3

conn = sqlite3.connect('secrets.db')
cursor = conn.cursor()

# Try to add the column – ignore if it already exists
try:
    cursor.execute("ALTER TABLE secrets ADD COLUMN text_ciphertext TEXT")
    print("✅ Column 'text_ciphertext' added successfully.")
except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e):
        print("ℹ️ Column already exists – nothing to do.")
    elif "no such table" in str(e):
        print("❌ Table 'secrets' does not exist yet. Start the app once and try again.")
    else:
        raise

conn.commit()
conn.close()