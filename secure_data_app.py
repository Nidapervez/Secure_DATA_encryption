import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate a key (this will remain fixed for the session)
if 'key' not in st.session_state:
    st.session_state['key'] = Fernet.generate_key()

cipher = Fernet(st.session_state['key'])

# Session state initialization
if 'stored_data' not in st.session_state:
    st.session_state['stored_data'] = {}

if 'failed_attempts' not in st.session_state:
    st.session_state['failed_attempts'] = 0

if 'just_logged_in' not in st.session_state:
    st.session_state['just_logged_in'] = False

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt text
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt text
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for value in st.session_state['stored_data'].values():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state['failed_attempts'] = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state['failed_attempts'] += 1
    return None

# UI setup
st.set_page_config(page_title="Secure Data App", page_icon="🔐")
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

# Store Data
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            # Store the encrypted data and the hashed passkey
            st.session_state['stored_data'][encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language='text')
        else:
            st.error("⚠️ Both fields are required!")

# Retrieve Data
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")

    # Show message after login
    if st.session_state['just_logged_in']:
        st.success("🔓 Login successful! You can now decrypt your data.")
        st.session_state['just_logged_in'] = False

    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                attempts_left = 3 - st.session_state['failed_attempts']
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")

                if st.session_state['failed_attempts'] >= 3:
                    st.warning("🔒 Too many failed attempts! Please log in again from the sidebar.")
                    st.session_state['failed_attempts'] = 0
                    st.session_state['just_logged_in'] = False
        else:
            st.error("⚠️ Both fields are required!")

# Login Page
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded password
            st.session_state['failed_attempts'] = 0
            st.session_state['just_logged_in'] = True
            st.success("✅ Reauthorized successfully! Go to 'Retrieve Data' from sidebar.")
        else:
            st.error("❌ Incorrect password!")
