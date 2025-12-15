import socket
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

run = True
DEBUG = False

def debug_print(*args):
    if DEBUG:
        print(*args)

# ENCRYPT + SIGN 
def encrypt_and_sign(message, receiver_pub_key, sender_priv_key):
    debug_print("\n --- Encrypting & Signing Message ---")
    debug_print(" Plaintext:", message)

    # Compute hash
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    message_hash = digest.finalize()
    debug_print(" SHA-256 Hash of message:", message_hash.hex())

    # Encrypt
    ciphertext = receiver_pub_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    debug_print(" Ciphertext (raw bytes):", ciphertext.hex())

    # Sign
    signature = sender_priv_key.sign(
        message_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    debug_print(" Signature (raw bytes):", signature.hex())

    package = base64.b64encode(ciphertext) + b"::" + base64.b64encode(signature)
    debug_print(" Outgoing Base64 Package:", package.decode())
    debug_print(" --- Encryption & Signing DONE ---")

    return package

#  DECRYPT + VERIFY 
def decrypt_and_verify(package, receiver_priv_key, sender_pub_key):
    debug_print("\n --- Decrypting & Verifying Package ---")
    ciphertext_b64, signature_b64 = package.split(b"::")
    ciphertext = base64.b64decode(ciphertext_b64)
    signature = base64.b64decode(signature_b64)
    debug_print(" Received Ciphertext (raw bytes):", ciphertext.hex())
    debug_print(" Received Signature (raw bytes):", signature.hex())

    # Decrypt
    plaintext = receiver_priv_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    debug_print(" Decrypted Plaintext:", plaintext)

    # Compute hash
    digest = hashes.Hash(hashes.SHA256())
    digest.update(plaintext.encode())
    message_hash = digest.finalize()
    debug_print(" SHA-256 Hash of decrypted message:", message_hash.hex())

    # Verify signature
    try:
        sender_pub_key.verify(
            signature,
            message_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        verified = True
        debug_print(" Signature Verified Successfully")
    except:
        verified = False
        debug_print(" Signature Verification FAILED")

    debug_print(" --- Decrypt + Verify DONE ---")
    return plaintext, verified

#  GENERATE KEYS 
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
).decode()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

debug_print("\n--- CLIENT RSA KEYS ---")
debug_print(private_pem)
debug_print(public_pem.decode())
debug_print("------")

server_public_key = None

#  RECEIVING LOOP 
def receiveMsgFromServer(conn):
    global run, server_public_key
    while run:
        try:
            data = conn.recv(8192)
            if not data:
                continue

            if server_public_key is None:
                server_public_key = serialization.load_pem_public_key(data)
                debug_print("\nReceived server public key:")
                debug_print(data.decode())
                conn.sendall(public_pem)
                debug_print("Sent client public key to server.")
                continue

            plaintext, verified = decrypt_and_verify(data, private_key, server_public_key)
            print(f"\nServer says: {plaintext}")
            if DEBUG:
                print("[Signature Verified]" if verified else "[Signature FAILED]")

        except Exception as e:
            debug_print("Error receiving:", e)
            run = False
    conn.close()

#  MAIN 
if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 8000))
    print("Connected to server.\n")

    rcv = Thread(target=receiveMsgFromServer, args=(s,))
    rcv.start()

    while run:
        try:
            msg = input("Client: ")
            if server_public_key:
                package = encrypt_and_sign(msg, server_public_key, private_key)
                s.sendall(package)
            else:
                print("Waiting for server public key...")
        except Exception as e:
            debug_print("Error sending:", e)
            run = False

    s.close()
