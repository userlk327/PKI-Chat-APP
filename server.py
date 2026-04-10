"""
server.py
---------
PKI-Based Chat Server

How it works:
  1. Loads its own RSA private key (server_private.pem).
  2. Accepts multiple client connections (one thread per client).
  3. On connect, exchanges public keys with the client.
  4. Every incoming message is a JSON packet containing:
       - "enc_key"  : AES session key encrypted with the SERVER's RSA public key
       - "nonce"    : AES-EAX nonce (base64)
       - "ciphertext": AES-encrypted message body (base64)
       - "tag"      : AES-EAX authentication tag (base64)
       - "sender"   : plain-text username (not secret)
  5. Server decrypts the AES session key with its RSA private key,
     then decrypts the message body with AES-EAX.
  6. Server re-encrypts the plaintext for EACH other client using
     that client's RSA public key and broadcasts it.

Run:
    python server.py
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


# ── Configuration ────────────────────────────────────────────────────────────
HOST        = "0.0.0.0"
PORT        = 8080
BUFFER_SIZE = 4096          # bytes for a single recv()
DELIMITER   = b"<<END>>"   # message framing delimiter


# ── Load server keys ──────────────────────────────────────────────────────────
def load_server_keys():
    if not os.path.exists("server_private.pem"):
        raise FileNotFoundError(
            "server_private.pem not found. Run generate_keys.py first."
        )
    with open("server_private.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    with open("server_public.pem", "rb") as f:
        public_key  = RSA.import_key(f.read())
    return private_key, public_key


# ── Helpers ───────────────────────────────────────────────────────────────────
def recv_delimited(sock: socket.socket) -> bytes:
    """Read bytes from sock until DELIMITER is found. Returns the payload."""
    data = b""
    while DELIMITER not in data:
        chunk = sock.recv(BUFFER_SIZE)
        if not chunk:
            raise ConnectionError("Client disconnected.")
        data += chunk
    return data.split(DELIMITER)[0]


def send_delimited(sock: socket.socket, payload: bytes) -> None:
    """Send payload followed by DELIMITER."""
    sock.sendall(payload + DELIMITER)


def encrypt_for_client(plaintext: bytes, client_public_key: RSA.RsaKey) -> dict:
    """
    Encrypt *plaintext* for a specific client:
      1. Generate a fresh AES-256 session key.
      2. Encrypt plaintext with AES-EAX (authenticated encryption).
      3. Encrypt the AES session key with the client's RSA public key.
    Returns a dict ready to be JSON-serialised and sent.
    """
    session_key = get_random_bytes(32)              # AES-256

    # AES-EAX gives us authenticated encryption (confidentiality + integrity)
    aes_cipher  = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)

    # Encrypt session key with recipient's RSA public key
    rsa_cipher  = PKCS1_OAEP.new(client_public_key)
    enc_key     = rsa_cipher.encrypt(session_key)

    return {
        "enc_key":    base64.b64encode(enc_key).decode(),
        "nonce":      base64.b64encode(aes_cipher.nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag":        base64.b64encode(tag).decode(),
    }


def decrypt_from_client(packet: dict, server_private_key: RSA.RsaKey) -> bytes:
    """
    Reverse of encrypt_for_client:
      1. Decrypt AES session key with the server's RSA private key.
      2. Decrypt ciphertext with AES-EAX and verify the tag.
    Returns plaintext bytes.
    """
    enc_key    = base64.b64decode(packet["enc_key"])
    nonce      = base64.b64decode(packet["nonce"])
    ciphertext = base64.b64decode(packet["ciphertext"])
    tag        = base64.b64decode(packet["tag"])

    rsa_cipher  = PKCS1_OAEP.new(server_private_key)
    session_key = rsa_cipher.decrypt(enc_key)

    aes_cipher  = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    plaintext   = aes_cipher.decrypt_and_verify(ciphertext, tag)  # raises on tamper
    return plaintext


def verify_signature(plaintext: bytes, signature_b64: str,
                     client_public_key: RSA.RsaKey) -> bool:
    """
    Verify the RSA-PKCS1v15 digital signature sent by the client.
    Returns True if the signature is valid, False otherwise.
    This proves the message was sent by the holder of the client's private key.
    """
    try:
        signature = base64.b64decode(signature_b64)
        digest    = SHA256.new(plaintext)
        pkcs1_15.new(client_public_key).verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False


# ── Shared state (protected by a lock) ───────────────────────────────────────
clients_lock = threading.Lock()
# clients: { conn -> {"name": str, "public_key": RSA.RsaKey} }
clients: dict = {}


def broadcast(message_text: str, sender_name: str, sender_conn: socket.socket,
              server_private_key: RSA.RsaKey) -> None:
    """
    Re-encrypt *message_text* for every connected client (except the sender)
    and send it.
    """
    payload_bytes = message_text.encode()

    with clients_lock:
        targets = [(conn, info) for conn, info in clients.items()
                   if conn is not sender_conn]

    for conn, info in targets:
        try:
            packet = encrypt_for_client(payload_bytes, info["public_key"])
            packet["sender"] = sender_name          # plain-text label
            raw = json.dumps(packet).encode()
            send_delimited(conn, raw)
        except Exception as exc:
            print(f"[!] Failed to send to {info['name']}: {exc}")


# ── Per-client thread ─────────────────────────────────────────────────────────
def handle_client(conn: socket.socket, addr, server_private_key: RSA.RsaKey,
                  server_public_key: RSA.RsaKey) -> None:
    """
    Full lifecycle of a single client connection:
      handshake → receive username → exchange public keys → relay messages.
    """
    client_name = "Unknown"
    try:
        # ── Step 1: receive client's username ─────────────────────────────────
        client_name = recv_delimited(conn).decode().strip()
        print(f"[+] '{client_name}' connected from {addr[0]}:{addr[1]}")

        # ── Step 2: send server's public key to client ───────────────────────
        server_pub_pem = server_public_key.export_key("PEM")
        send_delimited(conn, server_pub_pem)

        # ── Step 3: receive client's public key ──────────────────────────────
        client_pub_pem = recv_delimited(conn)
        client_pub_key = RSA.import_key(client_pub_pem)

        # ── Step 4: register client ───────────────────────────────────────────
        with clients_lock:
            clients[conn] = {"name": client_name, "public_key": client_pub_key}

        # Notify everyone
        join_msg = f"*** {client_name} has joined the chat ***"
        print(f"[*] {join_msg}")
        broadcast(join_msg, "SERVER", conn, server_private_key)

        # ── Step 5: message relay loop ────────────────────────────────────────
        while True:
            raw = recv_delimited(conn)
            packet = json.loads(raw.decode())

            # Decrypt message content
            plaintext = decrypt_from_client(packet, server_private_key)
            message   = plaintext.decode()

            # Verify digital signature — proves the sender holds their private key
            signature = packet.get("signature", "")
            client_pub_key = clients[conn]["public_key"]
            if not verify_signature(plaintext, signature, client_pub_key):
                print(f"[!] Signature verification FAILED for '{client_name}' — message dropped.")
                continue
            print(f"[MSG] {client_name} (verified): {message}")

            # Broadcast re-encrypted message to all other clients
            broadcast(f"{client_name}: {message}", client_name, conn,
                      server_private_key)

    except (ConnectionError, ConnectionResetError):
        print(f"[-] '{client_name}' disconnected.")
    except Exception as exc:
        print(f"[!] Error with '{client_name}': {exc}")
    finally:
        with clients_lock:
            clients.pop(conn, None)
        conn.close()
        leave_msg = f"*** {client_name} has left the chat ***"
        print(f"[*] {leave_msg}")
        broadcast(leave_msg, "SERVER", conn, server_private_key)


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    server_private_key, server_public_key = load_server_keys()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(10)

    host_name = socket.gethostname()
    ip        = socket.gethostbyname(host_name)
    print("=" * 55)
    print("  PKI-Based Secure Chat Server")
    print("=" * 55)
    print("  Binding Successful!")
    print(f"  This is your IP : {ip}")
    print(f"  Listening on port {PORT}")
    print(f"  RSA keys loaded ✓")
    print("=" * 55)
    print("  Waiting for connections ...\n")

    try:
        while True:
            conn, addr = server_sock.accept()
            t = threading.Thread(
                target=handle_client,
                args=(conn, addr, server_private_key, server_public_key),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()