# modules/sha_module.py

import hashlib

def hash_text_input():
    text = input("Enter the text to hash using SHA256: ")
    hashed = hashlib.sha256(text.encode()).hexdigest()
    print(f"\n🔐 SHA256 Hash:\n{hashed}")

def hash_file():
    file_path = input("Enter the file path to hash: ").strip()
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()
            hashed = hashlib.sha256(file_data).hexdigest()
            print(f"\n📁 SHA256 Hash of file '{file_path}':\n{hashed}")
    except FileNotFoundError:
        print("❌ File not found.")
    except Exception as e:
        print("❌ Error reading file:", e)

def sha_menu():
    while True:
        print("\n--- SHA256 Hashing ---")
        print("1. Hash Text Input")
        print("2. Hash a File")
        print("3. Back to Main Menu")

        choice = input("Select an option (1-3): ").strip()

        if choice == '1':
            hash_text_input()
        elif choice == '2':
            hash_file()
        elif choice == '3':
            break
        else:
            print("❌ Invalid choice. Please enter 1-3.")
