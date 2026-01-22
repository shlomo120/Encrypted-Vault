#!/usr/bin/env python3
import os
import getpass
import base64
import gzip
import random
import shutil
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

#pip install cryptography

class EncryptedVaultPS:
    ITERATIONS = 200

    @staticmethod
    def generate_random_name(original_name=""):
        """Generate random 12-character filename"""
        chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        name = ''.join(random.choice(chars) for _ in range(12))
        return f"{name}.txt"

    @staticmethod
    def save_original_name(name):
        """Encode original filename to base64"""
        return base64.b64encode(name.encode('utf-8')).decode('ascii')

    @staticmethod
    def load_original_name(base64_name):
        """Decode original filename from base64"""
        try:
            return base64.b64decode(base64_name).decode('utf-8')
        except:
            return None

    @staticmethod
    def protect_string(plain_text, passphrase):
        """Encrypt and compress string - compatible with PowerShell version"""
        # Compress with gzip
        plain_bytes = plain_text.encode('utf-8')
        compressed_bytes = gzip.compress(plain_bytes)

        # Generate random salt (16 bytes)
        salt = os.urandom(16)

        # Derive key using PBKDF2 with 200 iterations (matching PowerShell)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),  # Rfc2898DeriveBytes uses SHA1
            length=32 + 16,  # 32 for key + 16 for IV
            salt=salt,
            iterations=200,
            backend=default_backend()
        )
        key_material = kdf.derive(passphrase.encode('utf-8'))
        key = key_material[:32]  # AES-256 key
        iv = key_material[32:48]  # IV

        # Encrypt with AES
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Add PKCS7 padding
        block_size = 16
        padding_length = block_size - (len(compressed_bytes) % block_size)
        padded_data = compressed_bytes + bytes([padding_length] * padding_length)

        encrypted_bytes = encryptor.update(padded_data) + encryptor.finalize()

        # Combine salt + encrypted data
        output = salt + encrypted_bytes

        return base64.b64encode(output).decode('ascii')

    @staticmethod
    def unprotect_string(cipher_base64, passphrase):
        """Decrypt and decompress string - compatible with PowerShell version"""
        try:
            # Decode from base64
            in_bytes = base64.b64decode(cipher_base64)

            # Extract salt and cipher bytes
            salt = in_bytes[:16]
            cipher_bytes = in_bytes[16:]

            # Derive key using PBKDF2 with 200 iterations
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA1(),
                length=32 + 16,
                salt=salt,
                iterations=200,
                backend=default_backend()
            )
            key_material = kdf.derive(passphrase.encode('utf-8'))
            key = key_material[:32]
            iv = key_material[32:48]

            # Decrypt with AES
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_bytes = decryptor.update(cipher_bytes) + decryptor.finalize()

            # Remove PKCS7 padding
            padding_length = decrypted_bytes[-1]
            compressed_bytes = decrypted_bytes[:-padding_length]

            # Decompress
            plain_bytes = gzip.decompress(compressed_bytes)

            return plain_bytes.decode('utf-8')
        except Exception as e:
            print(f"Decryption error: {e}")
            return None

    @staticmethod
    def encrypt_file(input_file, output_file, passphrase, original_name):
        """Encrypt file - compatible with PowerShell format"""
        if not os.path.exists(input_file):
            return False

        # Read file and encode to base64
        with open(input_file, 'rb') as f:
            file_bytes = f.read()
        b64_data = base64.b64encode(file_bytes).decode('ascii')

        # Encrypt the base64 data
        protected_data = EncryptedVaultPS.protect_string(b64_data, passphrase)

        # Save original name
        name_data = EncryptedVaultPS.save_original_name(original_name)

        # Write to file with NAME header (UTF-8 with BOM to match PowerShell)
        with open(output_file, 'w', encoding='utf-8-sig') as f:
            f.write(f"NAME:{name_data}\n{protected_data}")

        return True

    @staticmethod
    def decrypt_file(input_file, output_file, passphrase):
        """Decrypt file - compatible with PowerShell format"""
        if not os.path.exists(input_file):
            return False

        try:
            # Read encrypted file with UTF-8-SIG to handle BOM
            with open(input_file, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().strip()  # Read NAME: header (BOM auto-removed)
                encrypted_data = f.read().strip()  # Read rest of file

            # Validate we have data
            if not encrypted_data:
                print("Invalid file format: missing encrypted data")
                return False

            # Decrypt
            decrypted_b64 = EncryptedVaultPS.unprotect_string(encrypted_data, passphrase)
            if not decrypted_b64:
                print("Decryption failed - wrong password?")
                return False

            # Decode from base64 to get original file bytes
            file_bytes = base64.b64decode(decrypted_b64)

            # Create output directory if needed
            output_dir = os.path.dirname(output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)

            # Write decrypted file
            with open(output_file, 'wb') as f:
                f.write(file_bytes)

            return True
        except Exception as e:
            print(f"Error decrypting file: {e}")
            return False

    @staticmethod
    def get_original_name(encrypted_file):
        """Extract original filename from encrypted file"""
        try:
            # Read with UTF-8-SIG to automatically remove BOM
            with open(encrypted_file, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().strip()

            if first_line.startswith('NAME:'):
                base64_name = first_line[5:]  # Remove 'NAME:' prefix
                return EncryptedVaultPS.load_original_name(base64_name)
        except:
            pass
        return None


def main():
    """Main interactive function for file encryption/decryption"""
    print("=" * 60)
    print("EncryptedVault v1.0 - Python Edition (PS Compatible)")
    print("=" * 60)
    print()

    action = input("Choose action (1=Encrypt, 2=Decrypt): ").strip()

    if action not in ['1', '2']:
        print("Error: Use 1 or 2 only!")
        return

    is_encrypt = (action == '1')

    # Get input file/folder
    source_path = input("Enter file or folder path: ").strip()

    if os.path.isfile(source_path):
        files = [Path(source_path)]
        is_folder = False
    elif os.path.isdir(source_path):
        files = list(Path(source_path).rglob('*'))
        files = [f for f in files if f.is_file()]
        is_folder = True
    else:
        print(f"Error: Path not found: {source_path}")
        return

    if not files:
        print("No files found!")
        return

    print(f"Found {len(files)} files")

    # Get destination
    dest_choice = input("Destination (1=In-place, 2=New folder): ").strip()

    if dest_choice == '2':
        dest_path = input("Enter destination folder: ").strip()
        os.makedirs(dest_path, exist_ok=True)
    else:
        dest_path = str(Path(source_path).parent) if not is_folder else source_path

    # Get password
    passphrase = getpass.getpass("Enter password: ")

    # Confirm
    confirm = input(f"Process {len(files)} files? (Y/N): ").strip().upper()
    if confirm != 'Y':
        print("Cancelled.")
        return

    # Process files
    success_count = 0
    for idx, file_path in enumerate(files, 1):
        percent = int((idx / len(files)) * 100)
        print(f"[{percent}%] Processing {idx}/{len(files)}: {file_path.name}")

        if is_encrypt:
            # Encrypt
            random_name = EncryptedVaultPS.generate_random_name()
            output_file = os.path.join(dest_path, random_name)

            if EncryptedVaultPS.encrypt_file(str(file_path), output_file, passphrase, file_path.name):
                success_count += 1
                print(f"  ✓ Encrypted: {file_path.name} -> {random_name}")
        else:
            # Decrypt
            original_name = EncryptedVaultPS.get_original_name(str(file_path))
            if not original_name:
                original_name = file_path.stem  # Use filename without extension

            output_file = os.path.join(dest_path, original_name)

            if EncryptedVaultPS.decrypt_file(str(file_path), output_file, passphrase):
                success_count += 1
                print(f"  ✓ Decrypted: {file_path.name} -> {original_name}")

    print()
    print("=" * 60)
    print(f"Completed! {success_count}/{len(files)} files processed successfully.")
    print("=" * 60)


if __name__ == "__main__":
    main()
