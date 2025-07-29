from modules.aes_module import aes_menu
from modules.rsa_module import rsa_menu
from modules.sha_module import sha_menu

def main():
    print("🔐 Welcome to the Real-Time Cryptography Toolkit 🔐\n")

    while True:
        print("\nChoose an option:")
        print("1. AES Encryption/Decryption (Symmetric)")
        print("2. RSA Key Generation + Encryption/Decryption (Asymmetric)")
        print("3. SHA256 Hashing (One-way)")
        print("4. Exit")

        choice = input("\nEnter your choice (1-4): ").strip()

        if choice == '1':
            aes_menu()
        elif choice == '2':
            rsa_menu()
        elif choice == '3':
            sha_menu()
        elif choice == '4':
            print("Goodbye! 👋")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 4.")

if __name__ == "__main__":
    main()
