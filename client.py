"""
client.py
---------
PKI-Based Chat Client

How it works:
  1. Loads the client's own RSA key pair (client_private.pem / client_public.pem).
  2. Connects to the server via TCP.
  3. Handshake:
       a. Sends username.
       b. Receives the server's RSA public key.
       c. Sends the client's RSA public key.
  4. Spawns a background thread to continuously receive and decrypt messages.
  5. Main thread reads user input, encrypts with AES (session key per message),
     wraps the session key with the server's RSA public key, and sends the packet.

Run:
    python client.py
"""

import socket
import threading
import json
import base64
import os

from Crypto.PublicKey  import RSA
from Crypto.Cipher     import PKCS1_OAEP, AES
from Crypto.Random     import get_random_bytes
from Crypto.Signature  import pkcs1_15
from Crypto.Hash       import SHA256


# ── Configuration ─────────────────────────────────────────────────────────────
PORT        = 8080
BUFFER_SIZE = 4096
DELIMITER   = b"<<END>>"


# ── Load client keys ──────────────────────────────────────────────────────────
def load_client_keys():
    if not os.path.exists("client_private.pem"):
        raise FileNotFoundError(
            "client_private.pem not found. Run generate_keys.py first."
        )
    with open("client_private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    with open("client_public.pem", "rb") as f:
        public_key  = RSA.import_key(f.read())
    return private_key, public_key


# ── Socket I/O helpers ────────────────────────────────────────────────────────
def recv_delimited(sock: socket.socket) -> bytes:
    """Read bytes from sock until DELIMITER is found. Returns the payload."""
    data = b""
    while DELIMITER not in data:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            raise ConnectionError("Server closed the connection.")
        data += chunk
    return data.split(DELIMITER)[0]


def send_delimited(sock: socket.socket, payload: bytes) -> None:
    """Send payload followed by DELIMITER."""
    sock.sendall(payload + DELIMITER)


# ── Crypto helpers ────────────────────────────────────────────────────────────
def sign_message(plaintext: bytes, client_private_key: RSA.RsaKey) -> str:
    """
    Create an RSA-PKCS1v15 digital signature over SHA-256 of the plaintext.
    The server uses the client's stored public key to verify authenticity.
    Returns the signature as a base64 string.
    """
    digest = SHA256.new(plaintext)
    signature = pkcs1_15.new(client_private_key).sign(digest)
    return base64.b64encode(signature).decode()


def encrypt_message(plaintext: bytes, server_public_key: RSA.RsaKey,
                    client_private_key: RSA.RsaKey) -> dict:
    """
    Encrypt and sign a message for the server:
      1. Sign the plaintext with the client's RSA private key (authenticity).
      2. Generate a fresh AES-256 session key.
      3. Encrypt the plaintext with AES-EAX (authenticated encryption).
      4. Encrypt the session key with the server's RSA public key.
    Returns a dict ready to be JSON-serialised.
    """
    session_key = get_random_bytes(32)          # AES-256

    aes_cipher  = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)

    rsa_cipher  = PKCS1_OAEP.new(server_public_key)
    enc_key     = rsa_cipher.encrypt(session_key)

    return {
        "enc_key":    base64.b64encode(enc_key).decode(),
        "nonce":      base64.b64encode(aes_cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag":        base64.b64encode(tag).decode(),
        "signature":  sign_message(plaintext, client_private_key),
    }


def decrypt_message(packet: dict, client_private_key: RSA.RsaKey) -> str:
    """
    Decrypt a message received from the server:
      1. Decrypt the AES session key with the client's RSA private key.
      2. Decrypt the ciphertext with AES-EAX and verify the tag.
    Returns the plaintext string.
    """
    enc_key    = base64.b64decode(packet["enc_key"])
    nonce      = base64.b64decode(packet["nonce"])
    ciphertext = base64.b64decode(packet["ciphertext"])
    tag        = base64.b64decode(packet["tag"])

    rsa_cipher  = PKCS1_OAEP.new(client_private_key)
    session_key = rsa_cipher.decrypt(enc_key)

    aes_cipher  = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    plaintext   = aes_cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()


# ── Background receiver thread ────────────────────────────────────────────────
def receive_messages(sock: socket.socket, client_private_key: RSA.RsaKey,
                     stop_event: threading.Event) -> None:
    """
    Continuously read encrypted packets from the server, decrypt them,
    and print to the terminal.
    """
    while not stop_event.is_set():
        try:
            raw    = recv_delimited(sock)
            packet = json.loads(raw.decode())
            sender = packet.get("sender", "?")
            text   = decrypt_message(packet, client_private_key)
            # Print on its own line, then re-display the prompt
            print(f"\r[{sender}] {text}")
            print("You: ", end="", flush=True)
        except (ConnectionError, OSError):
            if not stop_event.is_set():
                print("\n[!] Lost connection to the server.")
            break
        except Exception as exc:
            if not stop_event.is_set():
                print(f"\n[!] Receive error: {exc}")
            break


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    client_private_key, client_public_key = load_client_keys()

    print("=" * 55)
    print("  PKI-Based Secure Chat Client")
    print("=" * 55)

    username    = input("  Enter your username : ").strip() or "Anonymous"
    server_host = input("  Enter server IP     : ").strip()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((server_host, PORT))
    except ConnectionRefusedError:
        print(f"[!] Connection refused at {server_host}:{PORT}.")
        print("    Make sure the server is running before starting the client.")
        return
    except socket.gaierror:
        print(f"[!] Could not resolve address '{server_host}'.")
        print("    Enter a valid IP address (e.g. 127.0.0.1 for same machine,")
        print("    or the IP shown by 'This is your IP' on the server).")
        return
    except (TimeoutError, socket.timeout):
        print(f"[!] Connection timed out. '{server_host}' is unreachable or not responding.")
        print("    Check the IP address and make sure the server is running.")
        return
    sock.settimeout(None)

    # ── Handshake ─────────────────────────────────────────────────────────────
    # 1. Send username
    send_delimited(sock, username.encode())

    # 2. Receive server's public key
    server_pub_pem    = recv_delimited(sock)
    server_public_key = RSA.import_key(server_pub_pem)
    print("  Server public key received ✓")

    # 3. Send our public key
    send_delimited(sock, client_public_key.export_key("PEM"))
    print("  Client public key sent     ✓")

    print("=" * 55)
    print("  Connected! Type a message and press Enter.")
    print("  Type  'quit'  to exit.")
    print("=" * 55 + "\n")

    # ── Start receiver thread ─────────────────────────────────────────────────
    stop_event = threading.Event()
    recv_thread = threading.Thread(
        target=receive_messages,
        args=(sock, client_private_key, stop_event),
        daemon=True,
    )
    recv_thread.start()

    # ── Send loop (main thread) ───────────────────────────────────────────────
    try:
        while True:
            print("You: ", end="", flush=True)
            message = input()

            if message.lower() == "quit":
                print("[*] Disconnecting ...")
                break
            if not message.strip():
                continue

            try:
                packet = encrypt_message(message.encode(), server_public_key,
                                         client_private_key)
                send_delimited(sock, json.dumps(packet).encode())
            except Exception as exc:
                print(f"[!] Send error: {exc}")
                break
    except KeyboardInterrupt:
        print("\n[*] Interrupted.")
    finally:
        stop_event.set()
        sock.close()


if __name__ == "__main__":
    main()