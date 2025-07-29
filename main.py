import os
from modules.aes_module import aes_menu
from modules.rsa_module import rsa_menu
from modules.sha_module import sha_menu


def main():
    while True:
        print("""
🔐 Welcome to the Real-Time Cryptography Toolkit 🔐

Choose an option:
1. AES Encryption/Decryption
2. RSA Key Generation + Encryption/Decryption
3. SHA256 Hashing
4. Exit
        """)

        choice = input("Enter your choice: ")

        if choice == '1':
            aes_menu()
        elif choice == '2':
            rsa_menu()
        elif choice == '3':
            sha_menu()
        elif choice == '4':
            print("Exiting... Stay secure! 🔐")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()