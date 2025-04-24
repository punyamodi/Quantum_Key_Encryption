import streamlit as st
from PIL import Image
import numpy as np
import csv
import os
import qrcode
import io
import cv2
import base64

# Custom CSS for styling
st.markdown(
    """
    <style>
    .reportview-container { background: #f0f2f6; }
    .sidebar .sidebar-content { background: #262730; color: #fff; }
    h1, h2, h3, h4, h5, h6 { color: #31333F; }
    .stButton>button { color: white; background-color: #4CAF50; border: none; padding: 10px 24px; text-align: center; text-decoration: none; display: inline-block; font-size: 16px; margin: 4px 2px; cursor: pointer; border-radius: 5px; }
    .stTextInput>div>div>input { border: 1px solid #4CAF50; border-radius: 5px; padding: 8px; }
    .stTextArea>div>div>textarea { border: 1px solid #4CAF50; border-radius: 5px; padding: 8px; }

    /* Style for disabled text area */
    .stTextArea>div>div>textarea:disabled {
        background-color: #6c757d; /* Medium gray background */
        color: white; /* White text color */
        border: 1px solid #495057; /* Slightly darker border */
        opacity: 1; /* Ensure text is not faded */
        cursor: text; /* Indicate text is selectable */
    }

    .css-1egvi7u { background-color: #e5f8e6; border: 1px solid #4CAF50; color: #336600; padding: 10px; margin-bottom: 10px; border-radius: 5px; }
    .css-qrbaxs { background-color: #f8e5e6; border: 1px solid #e53935; color: #660033; padding: 10px; margin-bottom: 10px; border-radius: 5px; }
    div.row-widget.stRadio > div { display: flex; flex-direction: row; justify-content: flex-start; }
    div.row-widget.stRadio > div > label { background-color: #e1f5fe; color: #0d47a1; border: 1px solid #03a9f4; border-radius: 20px; padding: 5px 15px; margin-right: 10px; cursor: pointer; }
    div.row-widget.stRadio > div > label:hover { background-color: #bbdefb; }
    div.row-widget.stRadio > div > label:has(input[type="radio"]:checked) { background-color: #03a9f4; color: white; }
    </style>
    """,
    unsafe_allow_html=True,
)

# --- Utility Functions (unchanged) ---

def create_credentials_file():
    if not os.path.exists("user_credentials.csv"):
        with open("user_credentials.csv", "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["username", "password"])

def register_user(username, password):
    with open("user_credentials.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([username, password])
    st.success("Registration successful. Please log in.")

def login_user(username, password):
    if not os.path.exists("user_credentials.csv"):
        st.error("User credentials file not found. Please register first.")
        return False
    with open("user_credentials.csv", "r") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["username"] == username and row["password"] == password:
                st.session_state.logged_in = True
                st.session_state.username = username
                return True
    st.error("Invalid username or password. Please try again.")
    return False

def bb84_key_exchange(length):
    alice_bits = np.random.randint(2, size=length)
    alice_bases = np.random.randint(2, size=length)
    bob_bases = np.random.randint(2, size=length)
    sifted_indices = [i for i in range(length) if alice_bases[i] == bob_bases[i]]
    if not sifted_indices:
        print("Warning: No matching bases found in BB84 simulation.")
        return np.array([], dtype=np.uint8) # Return empty array
    sifted_key = alice_bits[sifted_indices]
    return sifted_key

def encrypt_message(message, key):
    if len(key) == 0:
        raise ValueError("Encryption key cannot be empty.")
    key_bytes = bytes(key)
    message_bytes = message.encode('utf-8')
    encrypted_bytes = bytearray()
    for i in range(len(message_bytes)):
        encrypted_byte = message_bytes[i] ^ key_bytes[i % len(key_bytes)]
        encrypted_bytes.append(encrypted_byte)
    return base64.b64encode(bytes(encrypted_bytes)).decode('utf-8')

def decrypt_message(encrypted_message_b64, key):
    if len(key) == 0:
        raise ValueError("Decryption key cannot be empty.")
    key_bytes = bytes(key)
    try:
        encrypted_bytes = base64.b64decode(encrypted_message_b64)
    except base64.binascii.Error:
        raise ValueError("Invalid Base64 format for encrypted message.")

    decrypted_bytes = bytearray()
    for i in range(len(encrypted_bytes)):
        decrypted_byte = encrypted_bytes[i] ^ key_bytes[i % len(key_bytes)]
        decrypted_bytes.append(decrypted_byte)
    try:
        return decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError:
        raise ValueError("Decryption failed. Key might be incorrect or data corrupted.")

def generate_qkd_key_pair(key_length):
    sender_key = np.random.randint(256, size=key_length, dtype=np.uint8)
    return sender_key, sender_key

def encrypt_image_qkd(image_data_flat, qkd_key):
    encrypted_image_data = bytearray()
    for i in range(len(image_data_flat)):
        encrypted_byte = image_data_flat[i] ^ qkd_key[i % len(qkd_key)]
        encrypted_image_data.append(encrypted_byte)
    return bytes(encrypted_image_data)

def decrypt_image_qkd(encrypted_image_data, qkd_key, image_shape):
    decrypted_image_data = bytearray()
    for i in range(len(encrypted_image_data)):
        decrypted_byte = encrypted_image_data[i] ^ qkd_key[i % len(qkd_key)]
        decrypted_image_data.append(decrypted_byte)

    expected_elements = np.prod(image_shape)
    if len(decrypted_image_data) != expected_elements:
        raise ValueError(f"Decrypted data size ({len(decrypted_image_data)}) does not match expected size ({expected_elements}) for shape {image_shape}")

    decrypted_array = np.frombuffer(bytes(decrypted_image_data), dtype=np.uint8)
    return decrypted_array.reshape(image_shape)

def generate_qr_code(shared_key):
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=4, border=2)
    max_qr_len = 250
    qr_data = shared_key[:max_qr_len]
    if len(shared_key) > max_qr_len:
        print(f"Warning: QR code truncated key data to {max_qr_len} chars.")
    qr.add_data(qr_data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="green", back_color="white")
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    return img_byte_arr.getvalue()

# --- Main Application ---
def main():
    create_credentials_file()

    # Initialize session state variables
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "chat_encrypted_message" not in st.session_state:
        st.session_state.chat_encrypted_message = None
    if "chat_shared_key" not in st.session_state:
        st.session_state.chat_shared_key = None
    if "chat_qr_code_bytes" not in st.session_state:
        st.session_state.chat_qr_code_bytes = None
    if "chat_decrypted_message" not in st.session_state:
        st.session_state.chat_decrypted_message = None
    if "img_encrypted_content" not in st.session_state:
        st.session_state.img_encrypted_content = None
    if "img_sender_key" not in st.session_state:
        st.session_state.img_sender_key = None
    if "img_original_filename" not in st.session_state:
        st.session_state.img_original_filename = None
    if "img_decrypted_result" not in st.session_state:
        st.session_state.img_decrypted_result = None


    # --- Login/Register Page ---
    if not st.session_state.logged_in:
        st.title("🔒 Lock Chat")
        st.subheader("Secure Messaging and Image Transfer with QKD Simulation")
        st.image("https://image.binance.vision/editor-uploads/bd1d649021654f8f9a9059e02a7c1278.gif", use_column_width=False, width=700)

        st.sidebar.title("Authentication")
        auth_option = st.sidebar.radio("Choose an option", ("Login", "Register"))

        if auth_option == "Register":
            st.sidebar.subheader("Register New Account")
            new_username = st.sidebar.text_input("Choose a Username", key="reg_user")
            new_password = st.sidebar.text_input("Choose a Password", type="password", key="reg_pass")
            if st.sidebar.button("Register"):
                if new_username and new_password:
                    register_user(new_username, new_password)
                else:
                    st.sidebar.error("Username and password cannot be empty.")

        elif auth_option == "Login":
            st.sidebar.subheader("Login to Your Account")
            username = st.sidebar.text_input("Username", key="login_user")
            password = st.sidebar.text_input("Password", type="password", key="login_pass")
            if st.sidebar.button("Login"):
                if username and password:
                    login_successful = login_user(username, password)
                    if login_successful:
                        # Clear previous session results on successful login
                        st.session_state.chat_encrypted_message = None
                        st.session_state.chat_shared_key = None
                        st.session_state.chat_qr_code_bytes = None
                        st.session_state.chat_decrypted_message = None
                        st.session_state.img_encrypted_content = None
                        st.session_state.img_sender_key = None
                        st.session_state.img_original_filename = None
                        st.session_state.img_decrypted_result = None
                        st.rerun()
                else:
                    st.sidebar.error("Please enter both username and password.")

    # --- Main Application Page (after login) ---
    if st.session_state.logged_in:
        st.sidebar.success(f"Logged in as: {st.session_state.username}")
        st.sidebar.title("Navigation")
        navigation_option = st.sidebar.radio("Go to:", ("Secure Chat Interface", "Image Encryption and Decryption"))

        if st.sidebar.button("Logout"):
            # Clear all session state on logout
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()


        # --- Secure Chat Interface ---
        if navigation_option == "Secure Chat Interface":
            st.header("💬 Secure Chat Interface")
            st.write(f"Welcome, {st.session_state.username}! Encrypt and decrypt your messages.")

            col1, col2 = st.columns(2)

            # --- Send Message Column ---
            with col1:
                st.subheader("Send Message")
                message_to_send = st.text_area("Type your message here:", height=150, key="msg_to_send_input")

                if st.button("Encrypt and Send"):
                    if message_to_send:
                        try:
                            st.success("Generating key and encrypting...")
                            initial_key_length = max(64, len(message_to_send) * 4)
                            shared_key_bits = bb84_key_exchange(initial_key_length)

                            if len(shared_key_bits) == 0:
                                st.error("Key exchange simulation failed (no matching bases). Please try again.")
                                st.session_state.chat_encrypted_message = None
                                st.session_state.chat_shared_key = None
                                st.session_state.chat_qr_code_bytes = None
                            else:
                                shared_key_int = list(shared_key_bits)
                                shared_key_str = ''.join(map(str, shared_key_bits))
                                encrypted_message_b64 = encrypt_message(message_to_send, shared_key_int)
                                qr_code_bytes = generate_qr_code(shared_key_str)

                                st.session_state.chat_encrypted_message = encrypted_message_b64
                                st.session_state.chat_shared_key = shared_key_str
                                st.session_state.chat_qr_code_bytes = qr_code_bytes

                        except Exception as e:
                            st.error(f"Encryption error: {str(e)}")
                            st.session_state.chat_encrypted_message = None
                            st.session_state.chat_shared_key = None
                            st.session_state.chat_qr_code_bytes = None
                    else:
                        st.warning("Please enter a message to send.")

                # Display stored encryption results
                if st.session_state.chat_encrypted_message:
                    st.text_area("Encrypted Message (Base64):", value=st.session_state.chat_encrypted_message, height=100, disabled=True, key="disp_enc_msg")
                if st.session_state.chat_shared_key:
                    st.text_area("Shared Key (bits):", value=st.session_state.chat_shared_key, height=68, disabled=True, key="disp_shared_key")
                if st.session_state.chat_qr_code_bytes:
                    st.image(st.session_state.chat_qr_code_bytes, caption="QR Code for Shared Key (partial if long)", width=150)

            # --- Receive Message Column ---
            with col2:
                st.subheader("Receive Message")
                encrypted_message_received_b64 = st.text_area("Paste encrypted message (Base64):", height=150, key="enc_msg_recv")
                shared_key_received_str = st.text_input("Enter the shared key (bits):", key="key_recv")

                if st.button("Decrypt Message"):
                    encrypted_message_received_b64 = encrypted_message_received_b64.strip()
                    shared_key_received_str = shared_key_received_str.strip()
                    if encrypted_message_received_b64 and shared_key_received_str:
                        try:
                            if not all(c in '01' for c in shared_key_received_str):
                                raise ValueError("Invalid characters in shared key. Only 0s and 1s are allowed.")
                            if not shared_key_received_str:
                                raise ValueError("Shared key cannot be empty.")

                            shared_key_received_int = list(map(int, shared_key_received_str))
                            decrypted_message = decrypt_message(encrypted_message_received_b64, shared_key_received_int)
                            st.session_state.chat_decrypted_message = decrypted_message
                            st.success("Message decrypted successfully!")
                        except ValueError as e:
                            st.error(f"Decryption error: {e}. Please check key/message format.")
                            st.session_state.chat_decrypted_message = None
                        except Exception as e:
                            st.error(f"An unexpected decryption error occurred: {str(e)}")
                            st.session_state.chat_decrypted_message = None
                    else:
                        st.warning("Please provide both the encrypted message and the shared key.")
                        st.session_state.chat_decrypted_message = None

                # Display stored decryption result
                if st.session_state.chat_decrypted_message:
                    st.text_area("Decrypted Message:", value=st.session_state.chat_decrypted_message, height=100, disabled=True, key="disp_dec_msg")


        # --- Image Encryption and Decryption ---
        elif navigation_option == "Image Encryption and Decryption":
            st.header("🖼️ Secure Image Transfer")
            st.write("Encrypt images using a randomly generated key, download the encrypted data and key, then decrypt later.")

            col1, col2 = st.columns(2)

            # --- Encrypt Image Column ---
            with col1:
                st.subheader("Encrypt Image")
                uploaded_file = st.file_uploader("Upload an image to encrypt", type=["jpg", "png", "jpeg"], key="img_upload")

                if uploaded_file is not None:
                    try:
                        image = Image.open(uploaded_file)
                        if image.mode != 'RGB':
                           image = image.convert('RGB')
                        st.image(image, caption="Original Image", use_column_width=True)

                        if st.button("Encrypt Image"):
                            try:
                                image_data = np.array(image)
                                image_shape = image_data.shape
                                image_data_flat = image_data.flatten()
                                key_length = len(image_data_flat)
                                sender_key, _ = generate_qkd_key_pair(key_length)

                                encrypted_image_data = encrypt_image_qkd(image_data_flat, sender_key)
                                encrypted_data_b64 = base64.b64encode(encrypted_image_data).decode('utf-8')
                                shape_str = ','.join(map(str, image_shape))
                                file_content = f"{shape_str}\n{encrypted_data_b64}"
                                sender_key_str = " ".join(map(str, sender_key))

                                st.session_state.img_encrypted_content = file_content
                                st.session_state.img_sender_key = sender_key_str
                                st.session_state.img_original_filename = uploaded_file.name
                                st.success("Image encrypted successfully!")

                            except Exception as e:
                                st.error(f"Encryption error: {str(e)}")
                                st.session_state.img_encrypted_content = None
                                st.session_state.img_sender_key = None
                                st.session_state.img_original_filename = None

                    except Exception as e:
                        st.error(f"Error processing uploaded image: {e}")
                        st.session_state.img_encrypted_content = None
                        st.session_state.img_sender_key = None
                        st.session_state.img_original_filename = None

                # Display download buttons and key if results are stored
                if st.session_state.img_sender_key:
                     # Use disabled text area for the key display as well
                     st.text_area("Encryption Key (Save this securely!)", value=st.session_state.img_sender_key, height=100, disabled=True, key="disp_img_key")
                if st.session_state.img_encrypted_content and st.session_state.img_original_filename:
                    st.download_button(
                        label="Download Encrypted Data File (.txt)",
                        data=st.session_state.img_encrypted_content,
                        file_name=f"encrypted_{st.session_state.img_original_filename}.txt",
                        mime="text/plain",
                        key="dl_enc_data"
                    )
                if st.session_state.img_sender_key and st.session_state.img_original_filename:
                    st.download_button(
                         label="Download Encryption Key (.txt)",
                         data=st.session_state.img_sender_key,
                         file_name=f"key_{st.session_state.img_original_filename}.txt",
                         mime="text/plain",
                         key="dl_enc_key"
                     )


            # --- Decrypt Image Column ---
            with col2:
                st.subheader("Decrypt Image")
                uploaded_encrypted_file = st.file_uploader("Upload the encrypted data file (.txt)", type=["txt"], key="enc_file_upload")
                key_source = st.radio("Key Source:", ("Paste Key", "Upload Key File"), key="key_src_option", horizontal=True)
                decryption_key_str = ""
                if key_source == "Paste Key":
                    decryption_key_str_pasted = st.text_area("Enter decryption key (space-separated numbers):", key="dec_key_input_paste", height=100)
                    if decryption_key_str_pasted:
                        decryption_key_str = decryption_key_str_pasted
                else:
                    uploaded_key_file = st.file_uploader("Upload the key file (.txt)", type=["txt"], key="key_file_upload")
                    if uploaded_key_file:
                        try:
                            key_from_file = uploaded_key_file.getvalue().decode("utf-8").strip()
                            # Display key from file in a disabled text area too
                            st.text_area("Key from file:", key_from_file, height=100, disabled=True, key="disp_key_from_file")
                            decryption_key_str = key_from_file
                        except Exception as e:
                            st.error(f"Error reading key file: {e}")
                            decryption_key_str = ""

                if st.button("Decrypt Image"):
                    decryption_key_str = decryption_key_str.strip()
                    if uploaded_encrypted_file is not None and decryption_key_str:
                        try:
                            encrypted_file_content = uploaded_encrypted_file.getvalue().decode("utf-8")
                            lines = encrypted_file_content.splitlines()

                            if len(lines) < 2:
                                raise ValueError("Invalid encrypted file format. Expected shape and data on separate lines.")

                            shape_str = lines[0]
                            encrypted_data_b64 = lines[1]
                            image_shape = tuple(map(int, shape_str.split(',')))
                            encrypted_image_data = base64.b64decode(encrypted_data_b64)

                            decryption_key_list = list(map(int, decryption_key_str.split()))
                            decryption_key = np.array(decryption_key_list, dtype=np.uint8)

                            decrypted_image_array = decrypt_image_qkd(encrypted_image_data, decryption_key, image_shape)
                            st.session_state.img_decrypted_result = Image.fromarray(decrypted_image_array.astype(np.uint8))
                            st.success("Image decrypted successfully!")

                        except ValueError as e:
                             st.error(f"Decryption error: Invalid format in key, encrypted file, or shape. Details: {e}")
                             st.session_state.img_decrypted_result = None
                        except base64.binascii.Error:
                             st.error("Decryption error: Invalid Base64 data in the uploaded file.")
                             st.session_state.img_decrypted_result = None
                        except Exception as e:
                             st.error(f"An unexpected error occurred during decryption: {str(e)}")
                             st.session_state.img_decrypted_result = None
                    else:
                        st.warning("Please upload the encrypted data file and provide the decryption key (either paste or upload file).")
                        st.session_state.img_decrypted_result = None

                # Display stored decrypted image
                if st.session_state.img_decrypted_result:
                    st.image(st.session_state.img_decrypted_result, caption="Decrypted Image", use_column_width=True)


if __name__ == "__main__":
    main()