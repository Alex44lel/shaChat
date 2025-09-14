# shaChat - Secure Chat Application

A secure, end-to-end encrypted chat application built with Python, featuring X.509 certificate-based authentication and modern cryptographic protocols.

## Overview

shaChat is a real-time messaging application that prioritizes security and privacy. It implements a robust client-server architecture with RSA asymmetric encryption, ChaCha20Poly1305 symmetric encryption, and X.509 certificate-based authentication to ensure secure communications between users.

## Features

- **🔐 End-to-End Encryption**: Messages are encrypted using RSA and ChaCha20Poly1305 algorithms
- **🗝️ Certificate-Based Authentication**: X.509 certificates for user and server authentication
- **💬 Real-Time Messaging**: WebSocket-based communication using Flask-SocketIO
- **🖥️ User-Friendly GUI**: Desktop client built with Tkinter
- **📊 SQLite Database**: Efficient local storage for users and chat history
- **🔑 Secure Key Management**: Automatic key generation and secure storage
- **👥 Multi-Client Support**: Support for multiple simultaneous clients

## Architecture

The application consists of several key components:

- **Server**: Flask-based server handling authentication, message routing, and database management
- **Client**: Tkinter-based GUI client for user interaction
- **Certificate Authority (AC1)**: Manages X.509 certificates for authentication
- **Encryption Module**: Handles all cryptographic operations
- **JSON Manager**: Manages key storage and configuration

## Security Features

- **RSA 2048-bit keys** for asymmetric encryption
- **ChaCha20Poly1305** for symmetric encryption of messages
- **X.509 certificates** for identity verification
- **Secure key derivation** with PBKDF2
- **Session token management** for authenticated connections
- **Certificate validation** with expiration checking

## Prerequisites

- Python 3.7+
- OpenSSL (for certificate management)
- All dependencies listed in `requirements.txt`

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Alex44lel/shaChat.git
   cd shaChat
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up the Certificate Authority (Optional)**
   ```bash
   cd src/ac1
   # Follow the certificate generation process if needed
   ```

## Usage

### Starting the Server

1. Navigate to the server directory:
   ```bash
   cd src/server
   ```

2. Run the server:
   ```bash
   python server.py
   ```

3. Enter the server password when prompted.

The server will start on `http://localhost:44444` by default.

### Running the Client

1. Open a new terminal and navigate to the client directory:
   ```bash
   cd src/client1
   ```

2. Run the client:
   ```bash
   python client.py
   ```

3. For additional clients, use the `client2` directory:
   ```bash
   cd src/client2
   python client.py
   ```

### First Time Setup

1. **Register a new user** through the client interface
2. The system will automatically generate:
   - RSA key pairs for encryption
   - X.509 certificates for authentication
   - Secure session tokens

3. **Login** with your credentials to start chatting securely


## Configuration

The application uses several configuration files:

- **Server**: Generates `json_keys.json` for key storage
- **Clients**: Generate individual key files and session tokens
- **Database**: SQLite database (`shachat.db`) for user management

## Development Notes

- The application was developed with a focus on cryptographic security
- Certificate validation includes expiration date checking and signature verification
- The system supports both pre-authenticated and authenticated user states
- All cryptographic operations use industry-standard libraries (`cryptography`)

## Security Considerations

- **Key Storage**: Private keys are stored encrypted with user passwords
- **Certificate Validation**: Full X.509 certificate chain validation
- **Session Management**: Secure token-based session handling
- **Database Security**: User passwords are properly salted and hashed

