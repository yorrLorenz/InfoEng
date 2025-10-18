import socket
from threading import Thread
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

run = True

# rsa key generator
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

#  public and private key for display
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
).decode()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("\n--------------------SERVER RSA KEYS --------------------")
print("[Server Private Key]:\n", private_pem)
print("[Server Public Key]:\n", public_pem.decode())
print("----------------------------------------------------------")

client_public_key = None


def receiveMsgFromClient(conn):
    global run, client_public_key
    while run:
        try:
            data = conn.recv(4096)
            if not data:
                continue

            # client public key for checking
            if client_public_key is None:
                client_public_key = serialization.load_pem_public_key(data)
                print("\nReceived client's public key:")
                print(data.decode())
                continue

            # showing encrypted message 
            print(f"\n[Encrypted message from client]: {base64.b64encode(data).decode()}")

            # decrypting message
            decrypted_msg = private_key.decrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"[Decrypted message]: {decrypted_msg.decode()}")

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
                encrypted_msg = client_public_key.encrypt(
                    msg.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print(f"[Encrypted message sent]: {base64.b64encode(encrypted_msg).decode()}")
                print(f"[Plaintext message]: {msg}")
                conn.sendall(encrypted_msg)
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

    # Send server public key to client
    conn.sendall(public_pem)
    print("Sent server public key to client.\n")
    return conn, addr, s


if __name__ == '__main__':
    conn, addr, s = listenConnection()

    rcv = Thread(target=receiveMsgFromClient, args=(conn,))
    rcv.start()

    send = Thread(target=sendMessage, args=(conn,))
    send.start()
