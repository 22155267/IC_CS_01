#!/usr/bin/env python3
"""
Crypto Utilities for Secure File Sharing
- AES-256 CBC encryption/decryption for files
- RSA-2048 keypair generation
- RSA encryption/decryption of AES keys
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# ---------------- RSA KEYPAIR ---------------- #
def generate_rsa_keypair(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return public_key, private_key

# ---------------- AES KEY ---------------- #
def generate_aes_key():
    return get_random_bytes(32)  # AES-256

# ---------------- AES FILE ENCRYPTION (FILE PATH VERSION) ---------------- #
def encrypt_file_aes(input_path: str, output_path: str) -> None:
    """
    Encrypt a file using AES-256-CBC
    Args:
        input_path: Path to original file
        output_path: Path to save encrypted file
    """
    # Generate a random AES key for this file
    aes_key = generate_aes_key()
    
    # Read the file
    with open(input_path, 'rb') as f:
        data = f.read()
    
    # Encrypt
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    
    # Save: [IV][Ciphertext]
    with open(output_path, 'wb') as f:
        f.write(iv + ciphertext)
    
    # Save the AES key separately (for now, save it next to encrypted file)
    key_path = output_path + '.key'
    with open(key_path, 'wb') as f:
        f.write(aes_key)

def decrypt_file_aes(input_path: str, output_path: str) -> None:
    """
    Decrypt a file using AES-256-CBC
    Args:
        input_path: Path to encrypted file
        output_path: Path to save decrypted file
    """
    # Read the AES key
    key_path = input_path + '.key'
    with open(key_path, 'rb') as f:
        aes_key = f.read()
    
    if len(aes_key) != 32:
        raise ValueError(f"AES key must be 32 bytes for AES-256, got {len(aes_key)} bytes")
    
    # Read encrypted file
    with open(input_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Extract IV and ciphertext
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    
    # Decrypt
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    # Save decrypted file
    with open(output_path, 'wb') as f:
        f.write(data)

# ---------------- AES DATA ENCRYPTION (BYTES VERSION) ---------------- #
def encrypt_data_aes(data: bytes, aes_key: bytes) -> bytes:
    if len(aes_key) != 32:
        raise ValueError(f"AES key must be 32 bytes for AES-256, got {len(aes_key)} bytes")
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return iv + ciphertext

def decrypt_data_aes(encrypted_data: bytes, aes_key: bytes) -> bytes:
    if len(aes_key) != 32:
        raise ValueError(f"AES key must be 32 bytes for AES-256, got {len(aes_key)} bytes")
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# ---------------- RSA ENCRYPT/DECRYPT AES KEY ---------------- #
def encrypt_aes_key_with_rsa(aes_key: bytes, rsa_public_key_pem: str) -> str:
    if len(aes_key) != 32:
        raise ValueError(f"AES key must be 32 bytes, got {len(aes_key)} bytes")
    rsa_key = RSA.import_key(rsa_public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_key).decode('utf-8')

def decrypt_aes_key_with_rsa(encrypted_aes_key_b64: str, rsa_private_key_pem: str) -> bytes:
    encrypted_key = base64.b64decode(encrypted_aes_key_b64)
    rsa_key = RSA.import_key(rsa_private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    decrypted_key = cipher_rsa.decrypt(encrypted_key)
    if len(decrypted_key) != 32:
        raise ValueError(f"Decrypted AES key must be 32 bytes, got {len(decrypted_key)} bytes")
    return decrypted_key

# ---------------- UTILITY ---------------- #
def export_aes_key_base64(aes_key: bytes) -> str:
    if len(aes_key) != 32:
        raise ValueError(f"AES key must be 32 bytes, got {len(aes_key)} bytes")
    return base64.b64encode(aes_key).decode('utf-8')

def import_aes_key_base64(b64: str) -> bytes:
    key = base64.b64decode(b64)
    if len(key) != 32:
        if len(key) < 32:
            key = key + b'\x00' * (32 - len(key))
        else:
            key = key[:32]
    return key