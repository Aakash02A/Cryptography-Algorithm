from cryptography.fernet import Fernet


def generate_key():
    key = Fernet.generate_key()
    with open("aes_key.key", "wb") as key_file:
        key_file.write(key)
    print("[+] AES Key generated and saved as 'aes_key.key'")


def load_key():
    try:
        with open("aes_key.key", "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print("[-] Key file not found. Generate a key first.")
        return None


def encrypt_message():
    key = load_key()
    if key is None:
        return
    fernet = Fernet(key)
    message = input("Enter message to encrypt: ").encode()
    encrypted = fernet.encrypt(message)
    print(f"Encrypted: {encrypted.decode()}")


def decrypt_message():
    key = load_key()
    if key is None:
        return
    fernet = Fernet(key)
    encrypted = input("Enter encrypted message: ").encode()
    try:
        decrypted = fernet.decrypt(encrypted)
        print(f"Decrypted: {decrypted.decode()}")
    except Exception as e:
        print(f"[-] Decryption failed: {e}")


def aes_menu():
    while True:
        print("""
AES Menu:
1. Generate AES Key
2. Encrypt Message
3. Decrypt Message
4. Back to Main Menu
        """)
        choice = input("Enter your choice: ")

        if choice == '1':
            generate_key()
        elif choice == '2':
            encrypt_message()
        elif choice == '3':
            decrypt_message()
        elif choice == '4':
            break
        else:
            print("Invalid choice. Try again.")
