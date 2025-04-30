from cryptography.fernet import Fernet
import os

# Key Management
KEY_FILE = "secret.key"

# Generate a new key if not already present
def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)

# Load the encryption key
def load_key():
    try:
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        raise FileNotFoundError("Encryption key file not found. Please generate the key first.")

# Encrypt File
def encrypt_file(file_path):
    generate_key()
    key = load_key()
    fernet = Fernet(key)

    try:
        # Read original file data
        with open(file_path, "rb") as file:
            original_data = file.read()

        encrypted_data = fernet.encrypt(original_data)

        # Save encrypted data
        encrypted_path = file_path + ".encrypted"
        with open(encrypted_path, "wb") as enc_file:
            enc_file.write(encrypted_data)

        # Ensure the original file is properly closed before deleting
        if os.path.exists(file_path):
            os.remove(file_path)

        return encrypted_path

    except Exception as e:
        print(f"❌ Error encrypting file: {e}")
        return None

# Decrypt File
def decrypt_file(encrypted_path):
    key = load_key()
    fernet = Fernet(key)

    try:
        # Read encrypted file data
        with open(encrypted_path, "rb") as enc_file:
            encrypted_data = enc_file.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        # Remove `.encrypted` from filename
        decrypted_path = encrypted_path.replace(".encrypted", "")

        with open(decrypted_path, "wb") as dec_file:
            dec_file.write(decrypted_data)

        # Ensure the encrypted file is properly closed before deleting
        if os.path.exists(encrypted_path):
            os.remove(encrypted_path)

        return decrypted_path

    except FileNotFoundError:
        print(f"❌ File '{encrypted_path}' not found.")
        return None
    except Exception as e:
        print(f"❌ Error decrypting file: {e}")
        return None
