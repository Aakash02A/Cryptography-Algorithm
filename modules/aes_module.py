from cryptography.fernet import Fernet
import os

def generate_key():
    key = Fernet.generate_key()
    with open("aes_key.key", "wb") as key_file:
        key_file.write(key)
    print("🔑 AES key generated and saved to 'aes_key.key'.")

def load_key():
    if not os.path.exists("aes_key.key"):
        print("⚠️ No AES key found. Generating a new one.")
        generate_key()
    with open("aes_key.key", "rb") as key_file:
        return key_file.read()

def encrypt_message():
    key = load_key()
    f = Fernet(key)
    message = input("Enter the message to encrypt: ").encode()
    encrypted = f.encrypt(message)
    print(f"\n🔐 Encrypted message:\n{encrypted.decode()}")

    save = input("\nDo you want to save the encrypted message to a file? (y/n): ").lower()
    if save == 'y':
        os.makedirs("samples", exist_ok=True)
        with open("samples/encrypted_output.txt", "wb") as f_out:
            f_out.write(encrypted)
        print("✅ Encrypted message saved to 'samples/encrypted_output.txt'.")

def decrypt_message():
    key = load_key()
    f = Fernet(key)

    choice = input("Decrypt from (1) Text input or (2) File? Enter 1 or 2: ").strip()
    if choice == '1':
        encrypted_message = input("Enter the encrypted message: ").encode()
    elif choice == '2':
        file_path = input("Enter path to the encrypted file: ")
        try:
            with open(file_path, "rb") as file:
                encrypted_message = file.read()
        except FileNotFoundError:
            print("❌ File not found.")
            return
    else:
        print("❌ Invalid choice.")
        return

    try:
        decrypted = f.decrypt(encrypted_message)
        print(f"\n🔓 Decrypted message:\n{decrypted.decode()}")
    except Exception as e:
        print("❌ Decryption failed. Reason:", e)

def aes_menu():
    while True:
        print("\n--- AES (Symmetric Encryption) ---")
        print("1. Generate AES Key")
        print("2. Encrypt a Message")
        print("3. Decrypt a Message")
        print("4. Back to Main Menu")

        choice = input("Select an option (1-4): ").strip()

        if choice == '1':
            generate_key()
        elif choice == '2':
            encrypt_message()
        elif choice == '3':
            decrypt_message()
        elif choice == '4':
            break
        else:
            print("❌ Invalid choice. Please enter 1-4.")
