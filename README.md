# Secure Communication IoT
The project is a software for both the client (IoT device like smartwatch) and a server (app server). The communication has encryption algorithms and prevents common attacks.

Secure Encrypted Communication System (Diffie-Hellman + ChaCha20)

This project implements a secure **Client-Server communication system** in C++. It uses modern cryptographic techniques such as **Diffie-Hellman key exchange** and **ChaCha20 encryption** to ensure confidentiality and integrity of messages.

The system supports:
- Secure handshake between client and server.
- Agreement on encryption parameters.
- Continuous encrypted message exchange.
- **Comprehensive logging system with clean console output**
- **Anti-replay attack protection with random nonces**
- **SHA-256 message integrity verification**

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

## Logging System

The application implements a comprehensive logging system:

- **Client logs**: Stored in `logs/client.log`
- **Server logs**: Stored in `logs/server.log`
- **Console output**: Clean and user-friendly messages
- **Log levels**: INFO, WARNING, ERROR, SECURITY, COMMUNICATION

### Console Output vs Logs

**Console shows:**
- Connection status
- Security alerts
- User interaction messages
- Communication flow

**Logs contain:**
- Detailed technical information
- Full message contents
- Cryptographic operations
- Error details
- Security events

---

## Security Features

- **Random Nonce Generation**: Each message uses cryptographically secure random nonces
- **Anti-Replay Protection**: Server validates nonce uniqueness per client
- **Message Integrity**: SHA-256 hashing verifies message authenticity
- **Encryption**: ChaCha20-Poly1305 provides confidentiality and integrity
- **Digital Signatures**: Ed25519 signatures for authentication
- **Key Exchange**: X25519 Elliptic Curve Diffie-Hellman

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
    "nounce": "<random_hex_nonce>",
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
    "nounce": "<random_hex_nonce>"
}
```

Simple message
```json
{
    "method": "simple_message",
    "message": "<encrypted_message_hex>",
    "nounce": "<random_hex_nonce>",
    "sha256": "<message_integrity_hash>"
}
```

## Server messages

Hello Response

```json
{
    "method": "WhatsUpFIUNAM",
    "server_ID": "<server id>",
    "nounce": "<random_hex_nonce>",
    "signature_hex": "<server signature>",
    "public_key_hex": "<server public key>",
    "long_term_public_key_hex": "<server long-term public key>"
}
```

Start secure conversation
```json
{
    "method": "StartConversation",
    "OK": "<status (e.g., 'ok')>",
    "nounce": "<random_hex_nonce>"
}
```

Simple response
```json
{
    "method": "conn_continue",
    "message": "<encrypted_response_hex>",
    "nounce": "<random_hex_nonce>"
}
```
