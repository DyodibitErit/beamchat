# BEAM - Encrypted Messenger

A secure, encrypted messaging and bulletin board application built with Django that features end-to-end encryption for all messages and files.

## Features

- **End-to-End Encryption**: All messages are encrypted using AES-128 encryption before storage
- **Secure File Uploads**: Encrypted file attachments with unique UUID-based naming
- **Bulletin Board**: Shared space for announcements and important messages
- **RESTful API**: Programmatic access to all functionality
- **Responsive Design**: Works on desktop and mobile devices
- **Dark Mode Support (ONLY V0.54 OR LOWER)**: Automatically adapts to user's preference

## Security Features

- All messages encrypted at rest using Fernet symmetric encryption
- Files stored with UUID-based names to prevent path traversal attacks
- Encryption key stored separately from data
- CSRF protection for web forms
- No sensitive data stored in plaintext

## Installation

1. Clone or download the repository
2. Ensure you have Python 3.7+ installed
3. Install required dependencies:

```bash
pip install django cryptography
