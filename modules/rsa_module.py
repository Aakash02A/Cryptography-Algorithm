from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

KEY_FOLDER = "rsa_keys"

def generate_rsa_keys():
    if not os.path.exists(KEY_FOLDER):
        os.makedirs(KEY_FOLDER)

    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(os.path.join(KEY_FOLDER, "private_key.pem"), "wb") as priv_file:
        priv_file.write(private_key)
    with open(os.path.join(KEY_FOLDER, "public_key.pem"), "wb") as pub_file:
        pub_file.write(public_key)

    print("✅ RSA Key Pair generated and saved in 'rsa_keys/' directory.")

def load_public_key():
    try:
        with open(os.path.join(KEY_FOLDER, "public_key.pem"), "rb") as pub_file:
            return RSA.import_key(pub_file.read())
    except FileNotFoundError:
        print("❌ Public key not found. Please generate keys first.")
        return None

def load_private_key():
    try:
        with open(os.path.join(KEY_FOLDER, "private_key.pem"), "rb") as priv_file:
            return RSA.import_key(priv_file.read())
    except FileNotFoundError:
        print("❌ Private key not found. Please generate keys first.")
        return None

def encrypt_rsa():
    public_key = load_public_key()
    if not public_key:
        return

    message = input("Enter the message to encrypt: ").encode()
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message)

    print(f"\n🔐 Encrypted message (in bytes):\n{encrypted}")
    
    save = input("\nSave encrypted message to a file? (y/n): ").lower()
    if save == 'y':
        with open("samples/rsa_encrypted.bin", "wb") as f:
            f.write(encrypted)
        print("✅ Saved to 'samples/rsa_encrypted.bin'.")

def decrypt_rsa():
    private_key = load_private_key()
    if not private_key:
        return

    choice = input("Decrypt from (1) Input bytes or (2) File? Enter 1 or 2: ").strip()

    if choice == '1':
        hex_data = input("Enter the encrypted byte string (paste bytes as shown): ")
        try:
            encrypted_data = eval(hex_data)
        except Exception as e:
            print("❌ Error reading input:", e)
            return
    elif choice == '2':
        path = input("Enter the file path of the encrypted data: ")
        try:
            with open(path, "rb") as f:
                encrypted_data = f.read()
        except FileNotFoundError:
            print("❌ File not found.")
            return
    else:
        print("❌ Invalid choice.")
        return

    try:
        cipher = PKCS1_OAEP.new(private_key)
        decrypted = cipher.decrypt(encrypted_data)
        print(f"\n🔓 Decrypted message:\n{decrypted.decode()}")
    except Exception as e:
        print("❌ Decryption failed. Reason:", e)

def rsa_menu():
    while True:
        print("\n--- RSA (Asymmetric Encryption) ---")
        print("1. Generate RSA Key Pair")
        print("2. Encrypt a Message with Public Key")
        print("3. Decrypt a Message with Private Key")
        print("4. Back to Main Menu")

        choice = input("Select an option (1-4): ").strip()

        if choice == '1':
            generate_rsa_keys()
        elif choice == '2':
            encrypt_rsa()
        elif choice == '3':
            decrypt_rsa()
        elif choice == '4':
            break
        else:
            print("❌ Invalid choice. Please enter 1-4.")
