import socket
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

run = True

def encrypt_and_sign(message, receiver_pub_key, sender_priv_key):
    ciphertext = receiver_pub_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    signature = sender_priv_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(ciphertext) + b"::" + base64.b64encode(signature)

def decrypt_and_verify(package, receiver_priv_key, sender_pub_key):
    ciphertext_b64, signature_b64 = package.split(b"::")
    ciphertext = base64.b64decode(ciphertext_b64)
    signature = base64.b64decode(signature_b64)
    plaintext = receiver_priv_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    try:
        sender_pub_key.verify(
            signature,
            plaintext.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        verified = True
    except:
        verified = False
    return plaintext, verified

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

print("\n-------------------- SERVER RSA KEYS --------------------")
print("[Server Private Key]:\n", private_pem)
print("[Server Public Key]:\n", public_pem.decode())
print("----------------------------------------------------------")

client_public_key = None

def receiveMsgFromClient(conn):
    global run, client_public_key
    while run:
        try:
            data = conn.recv(8192)
            if not data:
                continue
            if client_public_key is None:
                client_public_key = serialization.load_pem_public_key(data)
                print("\nReceived client public key:")
                print(data.decode())
                continue
            print(f"\n[Received package]: {data.decode()}")
            plaintext, verified = decrypt_and_verify(data, private_key, client_public_key)
            print(f"[Decrypted message]: {plaintext}")
            print("[Signature verified]" if verified else "[Signature verification FAILED]")
        except Exception as e:
            print("Error receiving:", e)
            run = False
    conn.close()

def sendMessage(conn):
    global run, client_public_key
    while run:
        try:
            msg = input("\nServer: ")
            if client_public_key:
                package = encrypt_and_sign(msg, client_public_key, private_key)
                print(f"[Sent package]: {package.decode()}")
                conn.sendall(package)
            else:
                print("Client public key not received yet.")
        except Exception as e:
            print("Error sending:", e)
            run = False

def listenConnection():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 8000))
    s.listen(1)
    conn, addr = s.accept()
    print("\nClient connected from:", addr)
    conn.sendall(public_pem)
    print("Sent server public key to client.\n")
    return conn, addr, s

if __name__ == '__main__':
    conn, addr, s = listenConnection()
    rcv = Thread(target=receiveMsgFromClient, args=(conn,))
    rcv.start()
    send = Thread(target=sendMessage, args=(conn,))
    send.start()
