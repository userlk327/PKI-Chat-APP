# PKI-Chat-APP

PKI-Based Secure Chat Application
A secure, multi-client chat application built with Python that uses Public Key Infrastructure (PKI) to ensure confidentiality, authenticity, and integrity of message

Project Description
This application implements a client-server chat system secured using:
RSA (2048-bit) for asymmetric encryption and digital signatures
AES-256 (EAX mode) for symmetric message encryption
TCP Sockets for reliable network communication
Digital Signatures (PKCS1v15 + SHA-256) to verify message authenticity


How It Works
Key Exchange (Handshake)

Server and client each have their own RSA key pair (public/private)
When a client connects, the server sends its public key to the client
The client sends its public key to the server

Sending a Message

Client generates a fresh AES-256 session key for each message
Client signs the message with its RSA private key (digital signature)
Client encrypts the message with the AES session key
Client encrypts the AES session key with the server's RSA public key
Both the encrypted message and encrypted session key are sent together

Receiving a Message

Server decrypts the AES session key using its RSA private key
Server decrypts the message using the AES session key
Server verifies the digital signature using the sender's public key
If verification passes → message is broadcast to all other clients
If verification fails → message is dropped

Message Broadcasting

Server re-encrypts the message for each recipient using their public key
Every client receives a message encrypted specifically for them