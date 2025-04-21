import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Constants
DATA_FILE = 'data.json'
SALT = b'secure_salt_Value'

# Streamlit config
st.set_page_config(page_title="DataWarden", page_icon="🔐", layout="centered")

# Sidebar
with st.sidebar:
    st.markdown("## 🔐 DataWarden")
    menu = ['Home','Login', 'Store Data', 'Retrieve Data']
    choice = st.radio("Select one of the following", menu)

# Session states
if 'authenticated_user' not in st.session_state:
    st.session_state.authenticated_user = None

# Helper functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Load stored data
stored_data = load_data()


if choice == 'Home':
    st.header("🔐 Welcome to DataWarden")
    st.markdown("""
    **DataWarden** is your personal vault for securing sensitive information.  
    Using strong encryption, this app ensures your data stays safe, private, and accessible **only by you**.

    ---

    ### 🚀 How It Works:
    1. 🔓 **Login** with your secure credentials.
    2. 💾 **Store** your private data safely (it's encrypted!).
    3. 📂 **Retrieve** your data using your personal passkey.

    ✅ All data is stored **locally and securely**, ensuring complete privacy and control.

    ---

    ### 🛠️ Tech Stack:
    - 🐍 Python 3
    - 📦 Streamlit (for UI)
    - 🔐 Cryptography (Fernet encryption)
    - 📂 JSON (for local data storage)
    - 🔑 PBKDF2 + SHA256 (for password hashing)

    ---

    ### 🛡️ Why Choose DataWarden?
    - Offline, local-only storage
    - No external server or tracking
    - Super simple and secure
    - Ideal for passwords, private notes, secret plans, and more!
    """)
    
    # Footer
    st.markdown("""---""")
    st.markdown(
        """
        <div style='text-align: center; padding: 10px; font-size: 16px; color: #888;'>
            ✨ Made with ❤️ by <strong style='color:#444;'>Ali Akbar</strong>
        </div>
        """,
        unsafe_allow_html=True
    )


if choice == 'Login':
    st.title("🔓 Login")
    st.subheader("Please enter your credentials")

    username = st.text_input('👤 Username')
    password = st.text_input('🔑 Password', type='password')
    confirm = st.text_input('🔁 Confirm Password', type='password')

    if st.button('🔓 Login'):
        if not username or not password or not confirm:
            st.error('🚫 All fields required!')
        elif password != confirm:
            st.error('🚫 Passwords do not match!')
        else:
            hashed = hash_password(password)
            if username not in stored_data:
                stored_data[username] = {
                    'password': hashed,
                    'data': []
                }
                save_data(stored_data)
                st.success('✅ New user created and logged in!')
                st.session_state.authenticated_user = username
            else:
                if stored_data[username]['password'] == hashed:
                    st.success('✅ Logged in successfully!')
                    st.session_state.authenticated_user = username
                else:
                    st.error('❌ Incorrect credentials!')

# STORE DATA
elif choice == 'Store Data':
    st.title("💾 Store Encrypted Data")

    if not st.session_state.authenticated_user:
        st.warning("⚠ Please login first.")
    else:
        data = st.text_area("📥 Enter data to store")
        passkey = st.text_input("🔐 Enter passkey", type='password')

        if st.button("🔐 Encrypt and Save Data"):
            if data and passkey:
                encrypted = encrypt_text(data, generate_key(passkey))
                stored_data[st.session_state.authenticated_user]['data'].append({
                    'encrypted': encrypted,
                    'passkey': passkey
                })
                save_data(stored_data)
                st.success("✅ Data encrypted and saved!")
            else:
                st.error("🚫 All fields are required!")

# RETRIEVE DATA
elif choice == 'Retrieve Data':
    st.title("📂 Retrieve Your Data")

    if not st.session_state.authenticated_user:
        st.warning("⚠ Please login first.")
    else:
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get('data', [])

        if not user_data:
            st.info("📭 No data stored yet.")
        else:
            for i, item in enumerate(user_data):
                st.markdown(f"#### 🔐 Encrypted Data {i+1}")
                st.code(item['encrypted'], language='text')
                passkey = st.text_input(f"Enter Passkey to Decrypt Data {i+1}", type='password', key=f"passkey_{i}")

                if st.button(f"🔓 Decrypt {i+1}", key=f"decrypt_{i}"):
                    if passkey:
                        result = decrypt_text(item['encrypted'], passkey)
                        if result:
                            st.success(f"✅ Decrypted: {result}")
                        else:
                            st.error("🚫 Decryption failed! Wrong passkey.")
                    else:
                        st.warning("⚠ Please enter passkey.")
