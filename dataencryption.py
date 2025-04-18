import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# --- Constants ---
DATA_FILE = "secure_data.json"
SALT = b'secret_salt'
LOCKOUT_DURATION = 60

# --- Session State Setup ---
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "faild_attempts" not in st.session_state:
    st.session_state.faild_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# --- Utility Functions ---
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, passkey):
    cipher = Fernet(generate_key(passkey))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, passkey):
    try:
        cipher = Fernet(generate_key(passkey))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

stored_data = load_data()

# --- UI Setup ---
st.title("🔐 Welcome to Secure Data Vault")
st.markdown("Your **private digital locker** for storing and retrieving confidential information securely.")

menu = ["🏠 Home", "📝 Register", "🔑 Login", "💾 Store Data", "📥 Retrieve Data"]
choice = st.sidebar.selectbox("🌐 Navigate through the app", menu)

# --- Home ---
if choice == "🏠 Home":
    st.subheader("Hey there! 👋")
    st.write("This app helps you **encrypt**, **store**, and **retrieve** your sensitive data.")
    st.markdown("🔐 All data is encrypted using strong cryptographic algorithms. Your secrets are safe here!")

# --- Register ---
elif choice == "📝 Register":
    st.subheader("👤 Create Your Account")
    username = st.text_input("Pick a username:")
    password = st.text_input("Create a password:", type="password")

    if st.button("✨ Register Me"):
        if username and password:
            if username in stored_data:
                st.warning("Oops! That username is already taken. Try something else.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("🎉 You're all set! You can now log in.")
        else:
            st.error("Please fill in both fields — we need both to proceed!")

# --- Login ---
elif choice == "🔑 Login":
    st.subheader("🔓 Log Back In")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"🚫 Too many failed attempts. Please try again in {remaining} seconds.")
    else:
        username = st.text_input("Username:")
        password = st.text_input("Password:", type="password")

        if st.button("🔑 Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.faild_attempts = 0
                st.success(f"Welcome back, {username}! 😊")
            else:
                st.session_state.faild_attempts += 1
                remaining = 3 - st.session_state.faild_attempts
                st.error(f"Incorrect credentials! You’ve got {remaining} tries left.")

                if st.session_state.faild_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("😓 Locked out for 60 seconds due to multiple failed attempts.")
                    st.stop()

# --- Store Data ---
elif choice == "💾 Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please log in first to store your data.")
    else:
        st.subheader("📦 Store Something Important")
        data = st.text_area("What do you want to secure today?")
        passkey = st.text_input("Create an encryption passphrase 🧪", type="password")

        if st.button("💾 Encrypt & Save"):
            if data and passkey:
                encrypted_data = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted_data)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("Make sure you enter both the data and a passphrase.")

# --- Retrieve Data ---
elif choice == "📥 Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please log in first to access your data.")
    else:
        st.subheader("🔍 Let’s Find Your Secrets")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("It looks like you haven’t saved anything yet.")
        else:
            st.write("Here are your encrypted entries 🔐:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("Paste the encrypted text you want to decrypt 🧩")
            passkey = st.text_input("Enter your decryption passphrase 🔑", type="password")

            if st.button("🔓 Decrypt It"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success("🎉 Here's your decrypted data:")
                    st.write(result)
                else:
                    st.error("😕 That didn’t work. Make sure the text and passphrase are correct.")

