import socket
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

run = True
DEBUG = False  # Set False to disable debug output

def debug_print(*args):
    if DEBUG:
        print(*args)

# ---------------- ENCRYPT + SIGN ----------------
def encrypt_and_sign(message, receiver_pub_key, sender_priv_key):
    debug_print("\n[DEBUG] --- Encrypting & Signing Message ---")
    debug_print("[DEBUG] Plaintext:", message)

    # Compute hash
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message.encode())
    message_hash = digest.finalize()
    debug_print("[DEBUG] SHA-256 Hash of message:", message_hash.hex())

    # Encrypt
    ciphertext = receiver_pub_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    debug_print("[DEBUG] Ciphertext (raw bytes):", ciphertext.hex())

    # Sign the hash
    signature = sender_priv_key.sign(
        message_hash,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    debug_print("[DEBUG] Signature (raw bytes):", signature.hex())

    # Combine into package
    package = base64.b64encode(ciphertext) + b"::" + base64.b64encode(signature)
    debug_print("[DEBUG] Outgoing Base64 Package:", package.decode())
    debug_print("[DEBUG] --- Encryption & Signing DONE ---")

    return package

# ---------------- DECRYPT + VERIFY ----------------
def decrypt_and_verify(package, receiver_priv_key, sender_pub_key):
    debug_print("\n[DEBUG] --- Decrypting & Verifying Package ---")
    ciphertext_b64, signature_b64 = package.split(b"::")
    ciphertext = base64.b64decode(ciphertext_b64)
    signature = base64.b64decode(signature_b64)
    debug_print("[DEBUG] Received Ciphertext (raw bytes):", ciphertext.hex())
    debug_print("[DEBUG] Received Signature (raw bytes):", signature.hex())

    # Decrypt
    plaintext = receiver_priv_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    debug_print("[DEBUG] Decrypted Plaintext:", plaintext)

    # Compute hash
    digest = hashes.Hash(hashes.SHA256())
    digest.update(plaintext.encode())
    message_hash = digest.finalize()
    debug_print("[DEBUG] SHA-256 Hash of decrypted message:", message_hash.hex())

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
        debug_print("[DEBUG] Signature Verified Successfully")
    except:
        verified = False
        debug_print("[DEBUG] Signature Verification FAILED")

    debug_print("[DEBUG] --- Decrypt + Verify DONE ---")
    return plaintext, verified

# ---------------- GENERATE KEYS ----------------
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

debug_print("\n-------------------- SERVER RSA KEYS --------------------")
debug_print(private_pem)
debug_print(public_pem.decode())
debug_print("----------------------------------------------------------")

client_public_key = None

# ---------------- RECEIVING LOOP ----------------
def receiveMsgFromClient(conn):
    global run, client_public_key
    while run:
        try:
            data = conn.recv(8192)
            if not data:
                continue

            if client_public_key is None:
                client_public_key = serialization.load_pem_public_key(data)
                debug_print("\nReceived client public key:")
                debug_print(data.decode())
                continue

            plaintext, verified = decrypt_and_verify(data, private_key, client_public_key)
            print(f"\nClient says: {plaintext}")
            if DEBUG:
                print("[Signature Verified]" if verified else "[Signature FAILED]")

        except Exception as e:
            debug_print("Error receiving:", e)
            run = False
    conn.close()

# ---------------- SENDING LOOP ----------------
def sendMessage(conn):
    global run, client_public_key
    while run:
        try:
            msg = input("Server: ")
            if client_public_key:
                package = encrypt_and_sign(msg, client_public_key, private_key)
                conn.sendall(package)
            else:
                print("Waiting for client public key...")
        except Exception as e:
            debug_print("Error sending:", e)
            run = False

# ---------------- SERVER LISTEN ----------------
def listenConnection():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 8000))
    s.listen(1)
    conn, addr = s.accept()
    print("Client connected:", addr)
    conn.sendall(public_pem)
    return conn, addr, s

# ---------------- MAIN ----------------
if __name__ == '__main__':
    conn, addr, s = listenConnection()

    rcv = Thread(target=receiveMsgFromClient, args=(conn,))
    rcv.start()

    send = Thread(target=sendMessage, args=(conn,))
    send.start()
