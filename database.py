import sqlite3
import bcrypt  # For password hashing

# Database Initialization
DB_FILE = "secure_vault.db"

# Create Tables
def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()

        # Users Table (With Role and Email Verification)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                verified INTEGER DEFAULT 0,
                role TEXT NOT NULL
            )
        """)

        # Files Table (For Tracking Uploaded Files)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                owner TEXT NOT NULL,
                encryption_key TEXT NOT NULL
            )
        """)

        conn.commit()
    print("[+] Database initialized successfully.")

# Password Hashing
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(input_password, stored_hash):
    return bcrypt.checkpw(input_password.encode('utf-8'), stored_hash.encode('utf-8'))

# Add New User
def add_user(username, password, email, role="user"):
    hashed_password = hash_password(password)

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, password, email, verified, role) VALUES (?, ?, ?, 0, ?)",
                           (username, hashed_password, email, role))
            conn.commit()
            print(f"[+] User '{username}' added successfully.")
        except sqlite3.IntegrityError:
            print(f"[!] Username or email already exists.")

# Get User Details
def get_user(username):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        return cursor.fetchone()

# Verify User Email
def verify_user(email):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET verified = 1 WHERE email = ?", (email,))
        conn.commit()

# Update Password (Step 2 - Forgot Password Feature)
def update_password(email, new_password):
    hashed_password = hash_password(new_password)

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, email))
        conn.commit()
        print(f"[+] Password updated successfully for {email}")

if __name__ == "__main__":
    init_db()

    # Add an admin account for testing
    add_user("admin", "admin123", "admin@example.com", role="admin")
