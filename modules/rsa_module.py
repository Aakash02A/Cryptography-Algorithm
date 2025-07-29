from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("rsa_private.pem", "wb") as prv_file:
        prv_file.write(private_key)

    with open("rsa_public.pem", "wb") as pub_file:
        pub_file.write(public_key)

    print("[+] RSA key pair generated and saved as 'rsa_private.pem' and 'rsa_public.pem'")


def load_keys():
    try:
        with open("rsa_private.pem", "rb") as prv_file:
            private_key = RSA.import_key(prv_file.read())
        with open("rsa_public.pem", "rb") as pub_file:
            public_key = RSA.import_key(pub_file.read())
        return private_key, public_key
    except FileNotFoundError:
        print("[-] RSA key files not found. Generate keys first.")
        return None, None


def encrypt_rsa():
    _, public_key = load_keys()
    if public_key is None:
        return
    message = input("Enter message to encrypt: ").encode()
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message)
    print(f"Encrypted (base64): {base64.b64encode(encrypted).decode()}")


def decrypt_rsa():
    private_key, _ = load_keys()
    if private_key is None:
        return
    encrypted_b64 = input("Enter base64 encrypted message: ").encode()
    try:
        encrypted = base64.b64decode(encrypted_b64)
        cipher = PKCS1_OAEP.new(private_key)
        decrypted = cipher.decrypt(encrypted)
        print(f"Decrypted: {decrypted.decode()}")
    except Exception as e:
        print(f"[-] Decryption failed: {e}")


def rsa_menu():
    while True:
        print("""
RSA Menu:
1. Generate RSA Key Pair
2. Encrypt Message
3. Decrypt Message
4. Back to Main Menu
        """)
        choice = input("Enter your choice: ")

        if choice == '1':
            generate_rsa_keys()
        elif choice == '2':
            encrypt_rsa()
        elif choice == '3':
            decrypt_rsa()
        elif choice == '4':
            break
        else:
            print("Invalid choice. Try again.")
