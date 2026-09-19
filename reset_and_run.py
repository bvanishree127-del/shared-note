import os
import sys
import subprocess
import time

# Kill any existing Flask processes (optional, may not work on Windows easily)
# We'll just ask user to close the terminal manually.

print("⚠️  This script will DELETE your existing database and reset everything.")
print("Make sure you have stopped your Flask app (Ctrl+C in the terminal).")
input("Press Enter to continue, or Ctrl+C to cancel...")

# Delete database and cache
if os.path.exists("secrets.db"):
    os.remove("secrets.db")
    print("✅ Deleted secrets.db")

import shutil
if os.path.exists("__pycache__"):
    shutil.rmtree("__pycache__")
    print("✅ Deleted __pycache__")

# Now run a one‑time setup that imports app and creates tables
print("Creating new database with the latest schema...")
from app import app, db
with app.app_context():
    db.drop_all()   # just in case
    db.create_all()
    print("✅ Database created with all columns including text_ciphertext.")

# Verify the column exists
import sqlite3
conn = sqlite3.connect("secrets.db")
cursor = conn.cursor()
cursor.execute("PRAGMA table_info(secrets)")
columns = [col[1] for col in cursor.fetchall()]
if 'text_ciphertext' in columns:
    print("✅ Verification: column 'text_ciphertext' exists.")
else:
    print("❌ Verification FAILED – column missing.")
    sys.exit(1)
conn.close()

print("\n✅ Reset complete. You can now start the app normally.")
print("Run: python app.py")