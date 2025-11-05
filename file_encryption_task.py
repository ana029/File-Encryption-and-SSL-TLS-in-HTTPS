from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend
import os

# STEP 1: Create message.txt
with open("message.txt", "w", encoding="utf-8") as f:
    f.write("This is a test message for encryption and decryption demonstration using RSA and AES.\n")

# Read the message
with open("message.txt", "rb") as f:
    message = f.read()

# STEP 2: RSA ENCRYPTION / DECRYPTION
# Generate RSA Key Pair (2048-bit)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Save Private Key
with open("private.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Save Public Key
with open("public.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

# Encrypt message with RSA public key
rsa_encrypted = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Save RSA Encrypted file
with open("message_rsa_encrypted.bin", "wb") as f:
    f.write(rsa_encrypted)

# Decrypt with Private Key
rsa_decrypted = private_key.decrypt(
    rsa_encrypted,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Save RSA Decrypted file
with open("message_rsa_decrypted.txt", "wb") as f:
    f.write(rsa_decrypted)


# STEP 3: AES-256 ENCRYPTION / DECRYPTION
# Generate AES key (32 bytes = 256 bits) and IV (16 bytes)
aes_key = os.urandom(32)
aes_iv = os.urandom(16)

with open("aes_key.bin", "wb") as f:
    f.write(aes_key)

with open("aes_iv.bin", "wb") as f:
    f.write(aes_iv)

# Encrypt message using AES-256 
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
encryptor = cipher.encryptor()

# Padding to 16 bytes
pad_len = 16 - (len(message) % 16)
padded_message = message + bytes([pad_len]) * pad_len

aes_encrypted = encryptor.update(padded_message) + encryptor.finalize()

with open("message_aes_encrypted.bin", "wb") as f:
    f.write(aes_encrypted)

# Decrypt AES message
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
decryptor = cipher.decryptor()
decrypted_padded = decryptor.update(aes_encrypted) + decryptor.finalize()

# Remove padding
pad_len = decrypted_padded[-1]
aes_decrypted = decrypted_padded[:-pad_len]

with open("message_aes_decrypted.txt", "wb") as f:
    f.write(aes_decrypted)


# STEP 4: Write Comparison RSA vs AES

with open("rsa_vs_aes.txt", "w", encoding="utf-8") as f:
    f.write("""RSA vs AES Comparison
---------------------------------------
RSA:
- Type: Asymmetric (uses Public & Private keys)
- Speed: Slower, computationally heavy
- Use-case: Secure key exchange, digital signatures, small data encryption
- Key size: Typically 2048 or 4096 bits
- Performance: Not suitable for large files

AES:
- Type: Symmetric (uses one shared key)
- Speed: Very fast and efficient for large data
- Use-case: File encryption, disk encryption, VPNs, etc.
- Key size: 128, 192, 256 bits
- Performance: Ideal for bulk encryption
""")

print("✅ All files generated successfully!")
