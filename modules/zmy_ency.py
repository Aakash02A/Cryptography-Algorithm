import random

def key_stream(key, length):
    random.seed(sum([ord(c) for c in key]))
    return [random.randint(0, 255) for _ in range(length)]

def encrypt(plaintext, key):
    data = plaintext.encode('utf-8')
    ks = key_stream(key, len(data))
    encrypted = bytes([b ^ k for b, k in zip(data, ks)])
    return encrypted

def decrypt(ciphertext, key):
    ks = key_stream(key, len(ciphertext))
    decrypted = bytes([b ^ k for b, k in zip(ciphertext, ks)])
    return decrypted.decode('utf-8')


def zmy_menu():
    while True:
        print("\nWelcome to work on new Enky Module...\n")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("0. Exit")

        choice = input("Enter task number: ")

        if choice == "1":
            plaintext = input("Enter message to encrypt: ")
            key = input("Enter key: ")
            cipher = encrypt(plaintext, key)
            print("Encrypted (bytes):", cipher)
        elif choice == "2":
            cipher_input = input("Enter bytes to decrypt (e.g., b'\\x01\\x02'): ")
            key = input("Enter key: ")
            try:
                cipher_bytes = eval(cipher_input)
                decrypted = decrypt(cipher_bytes, key)
                print("Decrypted message:", decrypted)
            except:
                print("Invalid input format for encrypted bytes.")
        elif choice == "0":
            print("Exiting...")
            break
        else:
            print("Invalid task number...")

zmy_menu()
