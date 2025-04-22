import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os

# Constants
DATA_FILE = "data.json"
KEY_FILE = "fernet.key"

# Helper: Generate/load key
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return Fernet(key)

cipher = load_key()

# Load or initialize data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# Session state for tracking failed attempts
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# Helper: Save data to file
def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

# Hash passkey using SHA-256
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data with validation
def decrypt_data(encrypted_text, passkey):
    encrypted_text = encrypted_text.strip()  # Trim whitespace
    hashed = hash_passkey(passkey)
    for key, value in stored_data.items():
        if key == encrypted_text and value["passkey"] == hashed:
            st.session_state.failed_attempts = 0
            try:
                return cipher.decrypt(encrypted_text.encode()).decode()
            except Exception as e:
                st.error(f"Decryption error: {e}")
                return None
    st.session_state.failed_attempts += 1
    return None

def rerun():
    # Toggle a dummy session state variable to force rerun
    if "rerun_toggle" not in st.session_state:
        st.session_state.rerun_toggle = False
    st.session_state.rerun_toggle = not st.session_state.rerun_toggle

# UI
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, key="main_nav")

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:", key="store_data")
    passkey = st.text_input("Enter Passkey:", type="password", key="store_passkey")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            stored_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            save_data()
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    if stored_data:
        encrypted_text = st.selectbox("Select Encrypted Data:", options=list(stored_data.keys()), key="retrieve_data")
    else:
        st.info("No stored data available.")
        encrypted_text = ""
    passkey = st.text_input("Enter Passkey:", type="password", key="retrieve_passkey")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success(f"✅ Decrypted Data: {result}")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password", key="login_pass")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            rerun()
        else:
            st.error("❌ Incorrect password!")
