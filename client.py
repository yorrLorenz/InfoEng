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

print("\n-------------------- CLIENT RSA KEYS --------------------")
print("[Client Private Key]:\n", private_pem)
print("[Client Public Key]:\n", public_pem.decode())
print("----------------------------------------------------------")

server_public_key = None


def receiveMsgFromServer(conn):
    global run, server_public_key
    while run:
        try:
            data = conn.recv(4096)
            if not data:
                continue

            # server public key for display
            if server_public_key is None:
                server_public_key = serialization.load_pem_public_key(data)
                print("\nReceived server's public key:")
                print(data.decode())
                conn.sendall(public_pem)
                print("Sent client public key to server.")
                continue

            # showing encrypted message
            print(f"\n[Encrypted message from server]: {base64.b64encode(data).decode()}")

            # decrpytion 
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


if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('127.0.0.1', 8000))
    print("\nConnected to server.")

    rcv = Thread(target=receiveMsgFromServer, args=(s,))
    rcv.start()

    while run:
        try:
            msg = input("\nClient: ")
            if server_public_key:
                encrypted_msg = server_public_key.encrypt(
                    msg.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print(f"[Encrypted message sent]: {base64.b64encode(encrypted_msg).decode()}")
                print(f"[Plaintext message]: {msg}")
                s.sendall(encrypted_msg)
            else:
                print("Waiting for server's public key")
        except Exception as e:
            print("Error sending:", e)
            run = False

    s.close()
