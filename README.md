# BEAM - Encrypted Messenger

A secure, encrypted messaging and bulletin board application built with Django that features end-to-end encryption for all messages and files.

## Features

- **End-to-End Encryption**: All messages are encrypted using AES-128 encryption before storage  
- **Secure File Uploads**: Encrypted file attachments with unique UUID-based naming  
- **Bulletin Board**: Shared space for announcements and important messages  
- **BSM (Between Server Messaging)**: Cross-server private messaging using unique Beam numbers (`xxx-xxx-xxx`)  
- **User Profiles**: Custom or default-generated profile pictures, registration date, and Beam number display  
- **Private Messaging**: Send direct messages using `m/username/message` syntax  
- **Message Editing**: Edit your last message using `s/old_word/new_word` syntax  
- **Admin Panel**: Manage bulletin board content and user bans (requires `admin` account)  
- **User Discovery**: Find other users on the same server and their Beam numbers  
- **RESTful API**: Programmatic access to all functionality  
- **Responsive Design**: Works on desktop and mobile devices  

## Security Features

- All messages encrypted at rest using Fernet symmetric encryption (based on AES-128)  
- Files stored with UUID-based names to prevent path traversal attacks  
- Encryption key stored separately from data in `encryption.key`  
- Passwords hashed using PBKDF2 with SHA-256 and random salt  
- CSRF protection for web forms  
- No sensitive data stored in plaintext  
- TLS 1.2+ enforced for HTTPS mode (older protocols disabled)  
- User session cookies are encrypted and expire after 1 week  

## Installation

1. Clone or download the repository  
2. Ensure you have Python 3.7+ installed  
3. Install required dependencies:

```bash
pip install django cryptography pillow requests
```

> Note: `ssl` is part of the Python standard library and does not need separate installation.

4. Run the application:

- For **HTTP (development)**:
  ```bash
  python app.py
  ```

- For **HTTPS (recommended)**:
  ```bash
  python app.py --https
  ```
  This will auto-generate a self-signed certificate (`cert.pem`, `key.pem`) if none is provided.

5. Access the app in your browser:
   - HTTP: `http://localhost:8000`
   - HTTPS: `https://localhost:8443`

> ⚠️ **Warning**: The default `SECRET_KEY` and auto-generated encryption key are for development only. In production, use strong secrets and secure key management.

## Usage

- **Register** a new account (username up to 10 characters)  
- **Log in** and start chatting  
- Use the **bulletin board** for public announcements (editable by admin)  
- Send **private messages** with `m/recipient_username/your message`  
- **Edit** your last message with `s/old/new`  
- Access your **BSM profile** to get your unique Beam number (e.g., `123-456-789`)  
- Use the **BSM Discovery** page to find other users on the same server  
- Admin functions (available only to user `admin`):
  - Edit bulletin board
  - Ban/unban users via `/admin/users`

## File Structure

- `chat_messages.txt` – encrypted chat history  
- `bulletin_board.txt` – encrypted bulletin content  
- `users.json` – encrypted user database (passwords, Beam numbers, profile pics)  
- `bsm.json` – encrypted cross-server BSM messages  
- `uploads/` – encrypted file attachments (stored with UUID names)  
- `profile_pics/` – user profile pictures  
- `encryption.key` – symmetric key for data encryption (keep secret!)  

## Limitations & Notes

- This is a **single-file Django app** for simplicity and portability—not suitable for high-load production without refactoring.  
- User authentication is session-cookie-based; no multi-factor authentication.  
- BSM (cross-server messaging) requires frontend JavaScript to complete delivery—backend only prepares and validates messages.  
- TLS support is built-in but uses self-signed certs by default; provide your own for production.  
