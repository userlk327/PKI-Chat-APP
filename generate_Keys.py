"""
generate_keys.py
----------------
Run this ONCE before starting the server or client.
It creates four .pem files in the current directory:
    server_private.pem  server_public.pem
    client_private.pem  client_public.pem
"""

from Crypto.PublicKey import RSA


def generate_and_save(name: str, bits: int = 2048) -> None:
    """Generate an RSA key pair and save private/public keys to .pem files."""
    print(f"[*] Generating {bits}-bit RSA key pair for '{name}' ...")
    key = RSA.generate(bits)

    private_path = f"{name}_private.pem"
    public_path  = f"{name}_public.pem"

    with open(private_path, "wb") as f:
        f.write(key.export_key("PEM"))          # PKCS#1 PEM format

    with open(public_path, "wb") as f:
        f.write(key.publickey().export_key("PEM"))

    print(f"    Saved: {private_path}  |  {public_path}")


if __name__ == "__main__":
    generate_and_save("server")
    generate_and_save("client")
    print("\n[+] All keys generated successfully. Keep the private keys secret!")