import streamlit as st
import json
import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

 
DATA_FILE = "secure_data.json"
MASTER_PASSWORD = "admin123"

# Fernet key generation
def generate_key(passkey: str) -> bytes:
    salt = b'static_salt'  
    kdf = PBKDF2HMAC(
        algorithm=hashlib.sha256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

 
def load_data():
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

stored_data = load_data()
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
 
st.title("🔐 Secure Data Storage System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)
 
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.write("Securely **store and retrieve data** with your own passkey.")

 
elif choice == "Store Data":
    st.subheader("📁 Store Data")

    username = st.text_input("Username")
    user_data = st.text_area("Enter Data to Encrypt")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Encrypt & Store"):
        if username and user_data and passkey:
            user_key = generate_key(passkey)
            cipher = Fernet(user_key)
            encrypted_text = cipher.encrypt(user_data.encode()).decode()

            stored_data[username] = {
                "encrypted_text": encrypted_text
            }
            save_data(stored_data)
            st.success("✅ Data stored securely!")
            st.code(encrypted_text)
        else:
            st.error("⚠️ All fields are required!")
 
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")

    if st.session_state.failed_attempts >= 3:
        st.warning("🔒 Too many failed attempts. Please reauthorize.")
        st.switch_page("Login")

    username = st.text_input("Username")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        if username in stored_data and passkey:
            try:
                encrypted_text = stored_data[username]["encrypted_text"]
                user_key = generate_key(passkey)
                cipher = Fernet(user_key)
                decrypted = cipher.decrypt(encrypted_text.encode()).decode()

                st.success(f"✅ Decrypted Data: {decrypted}")
                st.session_state.failed_attempts = 0
            except:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
        else:
            st.error("⚠️ Username or passkey is invalid")

 
elif choice == "Login":
    st.subheader("🔑 Login to Reauthorize")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.session_state.logged_in = True
            st.success("✅ Reauthorized! You can now try retrieving data again.")
        else:
            st.error("❌ Incorrect password!")
 
elif choice == "Logout":
    st.subheader("🚪 Logout")
    if st.session_state.logged_in:
        st.session_state.logged_in = False
        st.success("✅ Logged out successfully!")
    else:
        st.error("⚠️ You are not logged in.")