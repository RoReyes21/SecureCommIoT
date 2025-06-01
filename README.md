# Secure Communication IoT
The project is a software for both the client (IoT device like smartwatch) and a server (app server). The communication has encryption algorithms and prevents common attacks.

Secure Encrypted Communication System (Diffie-Hellman + ChaCha20)

This project implements a secure **Client-Server communication system** in C++. It uses modern cryptographic techniques such as **Diffie-Hellman key exchange** and **ChaCha20 encryption** to ensure confidentiality and integrity of messages.

The system supports:
- Secure handshake between client and server.
- Agreement on encryption parameters.
- Continuous encrypted message exchange.

---

## Libraries Used

This project uses the following libraries:

- libasio-dev — For asynchronous networking (socket communication).
- nlohmann-json3-dev — For JSON serialization and parsing.
- libsodium-dev — For cryptographic operations (Diffie-Hellman, ChaCha20).

---

## Installation (Linux)

Run the following commands to install the required dependencies:

```bash
sudo apt update
sudo apt install libasio-dev nlohmann-json3-dev libsodium-dev
```
---
## General outline
ToDo, put here a photo

## General communication
![alt text](diagram.png)

---
## Message Formats
## Client messages

Hello message
```json
{
    "method": "HelloFIUNAM",
    "device_ID": "<client id>",
    "nounce": <nonce>,
    "signature_hex": "<client signature>",
    "public_key_hex": "<client public key>",
    "long_term_public_key_hex": "<client long-term public key>"
}
```

Agree parameters message
```json
{
    "method": "AgreeParams",
    "algorithm": "<algorithm name>",
    "nounce": <nonce>
}
```

Simple message
```json
{
    "method": "simple_message",
    "message": "<your message>",
    "nounce": "<nonce>"
}
```

## Server messages

Hello Response

```json
{
    "method": "WhatsUpFIUNAM",
    "server_ID": "<server id>",
    "nounce": <nonce>,
    "signature_hex": "<server signature>",
    "public_key_hex": "<server public key>",
    "long_term_public_key_hex": "<server long-term public key>"
}
```

Start secure conversation
```json
{
    "method": "StartConversation",
    "OK": "<status (e.g., 'yes')>",
    "nounce": <nonce>
}
```

Simple response
```json
{
    "method": "conn_continue",
    "message": "<response message>",
    "nounce": "<nonce>"
}
```
