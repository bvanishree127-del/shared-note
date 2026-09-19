import os
import shutil
import sqlite3
from app import app, db

print("=== SecureShare Database Reset ===")

# Delete old database and cache
if os.path.exists("secrets.db"):
    os.remove("secrets.db")
    print("✅ Deleted secrets.db")
else:
    print("ℹ️ secrets.db not found – skipping.")

if os.path.exists("__pycache__"):
    shutil.rmtree("__pycache__")
    print("✅ Deleted __pycache__")

# Recreate tables from the latest model
with app.app_context():
    print("Creating tables with the latest schema...")
    db.drop_all()
    db.create_all()
    print("✅ Tables created.")

# Verify the column exists
conn = sqlite3.connect("secrets.db")
cursor = conn.cursor()
cursor.execute("PRAGMA table_info(secrets)")
columns = [col[1] for col in cursor.fetchall()]
conn.close()

if "text_ciphertext" in columns:
    print("✅ SUCCESS: column 'text_ciphertext' exists.")
else:
    print("❌ ERROR: column 'text_ciphertext' is MISSING.")
    print("   Check that app.py has: text_ciphertext = db.Column(db.Text, nullable=True)")
    exit(1)

print("=== Reset complete. You can now start the app. ===")