#BeamChat - self-hosted messenger

#WARNING: change the variable below to set a SECRET_KEY for the server (not changing this can lead to session hijacking, cookie files forging, CSRF vulnerabilities. we don't want that to happend, do we?)
DJ_SECRET_KEY = "CHANGEINPROD123"

import os
import json
from datetime import datetime
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.urls import path
from django.core.wsgi import get_wsgi_application
from django.conf import settings
from django.template import Template, Context
from django import forms
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
import ssl
import socket
from django.core.servers.basehttp import WSGIServer, WSGIRequestHandler
from django.core.handlers.wsgi import WSGIHandler
import uuid
import base64
import threading
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib
import hmac
import random
import string
from PIL import Image, ImageDraw, ImageFont
import io
import requests
import threading
from urllib.parse import urlparse
import sqlite3
from contextlib import contextmanager

class SSLWSGIServer(WSGIServer):
    """WSGI server with SSL support"""
    
    def __init__(self, *args, **kwargs):
        self.certfile = kwargs.pop('certfile', None)
        self.keyfile = kwargs.pop('keyfile', None)
        super().__init__(*args, **kwargs)
        
    def get_request(self):
        client, addr = super().get_request()
        if self.certfile and self.keyfile:
            # Wrap the socket with SSL
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(self.certfile, self.keyfile)
            context.options |= ssl.OP_NO_SSLv2
            context.options |= ssl.OP_NO_SSLv3
            context.options |= ssl.OP_NO_TLSv1
            context.options |= ssl.OP_NO_TLSv1_1
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL:!RC4:!MD5:!3DES')
            
            ssl_socket = context.wrap_socket(client, server_side=True)
            return ssl_socket, addr
        
        return client, addr

class SSLWSGIRequestHandler(WSGIRequestHandler):
    """Request handler for SSL connections"""
    
    def setup(self):
        self.connection = self.request
        self.rfile = self.connection.makefile('rb', -1)
        self.wfile = self.connection.makefile('wb', 0)

def generate_self_signed_cert(certfile='cert.pem', keyfile='key.pem'):
    """Generate a self-signed SSL certificate for development"""
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BEAM Chat"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    
    certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("127.0.0.1"),
        ]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # Write certificate file
    with open(certfile, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    # Write private key file
    with open(keyfile, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    
    return certfile, keyfile

def run_https_server(host='0.0.0.0', port=8443, certfile=None, keyfile=None):
    """Run the Django application with HTTPS support"""
    
    # Generate self-signed certificate if not provided
    if not certfile or not keyfile:
        print("Generating self-signed SSL certificate...")
        certfile, keyfile = generate_self_signed_cert()
        print(f"Certificate generated: {certfile}, {keyfile}")
    
    # Verify certificate files exist
    if not os.path.exists(certfile) or not os.path.exists(keyfile):
        raise FileNotFoundError("SSL certificate or key file not found")
    
    print(f"Starting HTTPS server on https://{host}:{port}")
    print("Using SSL certificate:", certfile)
    print("Using SSL key:", keyfile)
    
    # Create SSL server
    server = SSLWSGIServer(
        (host, port),
        SSLWSGIRequestHandler,
        certfile=certfile,
        keyfile=keyfile
    )
    
    # Set application
    server.set_app(application)
    
    # Start server
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server.server_close()

def run_http_server(host='0.0.0.0', port=8000):
    """Run the Django application with HTTP (for development)"""
    print(f"Starting HTTP server on http://{host}:{port}")
    from django.core.management import execute_from_command_line
    execute_from_command_line([__file__, 'runserver', f'{host}:{port}'])

# Configure Django settings
settings.configure(
    DEBUG=False,
    SECRET_KEY=DJ_SECRET_KEY,
    ROOT_URLCONF=__name__,
    ALLOWED_HOSTS=['*'],
    INSTALLED_APPS=[
        'django.contrib.staticfiles',
    ],
    TEMPLATES=[
        {
            'BACKEND': 'django.template.backends.django.DjangoTemplates',
            'DIRS': [],
            'APP_DIRS': False,
        },
    ],
    STATIC_URL='/static/',
    # Увеличим максимальный размер загружаемых файлов (50 МБ)
    DATA_UPLOAD_MAX_MEMORY_SIZE = 50 * 1024 * 1024,
)

# Configuration variables
UPLOAD_DIR = 'uploads'
PROFILE_PICS_DIR = 'profile_pics'
ENCRYPTION_KEY_FILE = 'encryption.key'
DATABASE_NAME = 'beam_chat.db'
A2A_FILE = 'bsm.a2a'
SESSION_COOKIE_NAME = 'beam_session'
BSM_VALIDATION_TIMEOUT = 10  # seconds
BSM_ENABLED = False
ADMIN_USERS = ['admin']

# Encryption setup
def get_encryption_key():
    """Get or create encryption key"""
    if os.path.exists(ENCRYPTION_KEY_FILE):
        with open(ENCRYPTION_KEY_FILE, 'rb') as f:
            return f.read()
    else:
        # Generate a new key
        key = Fernet.generate_key()
        with open(ENCRYPTION_KEY_FILE, 'wb') as f:
            f.write(key)
        return key

# Initialize encryption
ENCRYPTION_KEY = get_encryption_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

def encrypt_data(data):
    """Encrypt data using Fernet symmetric encryption"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return cipher_suite.encrypt(data).decode('utf-8')

def decrypt_data(encrypted_data):
    """Decrypt data using Fernet symmetric encryption"""
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode('utf-8')
    return cipher_suite.decrypt(encrypted_data).decode('utf-8')

def is_user_admin(username):
    """Check if a user is an admin"""
    return username in ADMIN_USERS


# Create upload directory if it doesn't exist
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# Create profile pictures directory if it doesn't exist
if not os.path.exists(PROFILE_PICS_DIR):
    os.makedirs(PROFILE_PICS_DIR)

def init_database():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            beam_number TEXT UNIQUE,
            profile_picture TEXT,
            created_at TEXT NOT NULL,
            last_login TEXT,
            banned INTEGER DEFAULT 0,
            ban_reason TEXT,
            banned_at TEXT
        )
    ''')
    
    # Chat messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            filename TEXT,
            file_url TEXT,
            is_private INTEGER DEFAULT 0,
            target_user TEXT,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')

    # BSM messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bsm_messages (
            message_id TEXT PRIMARY KEY,
            sender TEXT NOT NULL,
            sender_server TEXT,
            recipient_beam_number TEXT NOT NULL,
            recipient_local_number TEXT,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            status TEXT DEFAULT 'sent',
            validation_status TEXT DEFAULT 'pending',
            FOREIGN KEY (sender) REFERENCES users (username)
        )
    ''')
    
    # Bulletin board table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS bulletin_board (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    ''')
    
    # Groups table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            password_hash TEXT NOT NULL,
            emoji_picture TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_public INTEGER DEFAULT 0,
            FOREIGN KEY (created_by) REFERENCES users (username)
        )
    ''')

    # Group members table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            joined_at TEXT NOT NULL,
            role TEXT DEFAULT 'member',
            FOREIGN KEY (group_id) REFERENCES groups (id),
            FOREIGN KEY (username) REFERENCES users (username),
            UNIQUE(group_id, username)
        )
    ''')

    # Group messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS group_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            filename TEXT,
            file_url TEXT,
            FOREIGN KEY (group_id) REFERENCES groups (id),
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')
    
    # Insert default bulletin content if empty
    cursor.execute('SELECT COUNT(*) FROM bulletin_board')
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            'INSERT INTO bulletin_board (content, updated_at) VALUES (?, ?)',
            ('Bulletin board is empty.', datetime.now().isoformat())
        )
    
    conn.commit()
    conn.close()

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    try:
        yield conn
    finally:
        conn.close()

# Forms
class ChatMessageForm(forms.Form):
    message = forms.CharField(widget=forms.Textarea, required=False)
    file = forms.FileField(required=False)

class LoginForm(forms.Form):
    username = forms.CharField(max_length=50)
    password = forms.CharField(widget=forms.PasswordInput)

class RegisterForm(forms.Form):
    username = forms.CharField(max_length=10)
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

class ProfilePictureForm(forms.Form):
    profile_picture = forms.ImageField(required=False)

class CreateGroupForm(forms.Form):
    name = forms.CharField(max_length=50)
    description = forms.CharField(widget=forms.Textarea, required=False)
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)
    emoji_picture = forms.CharField(max_length=10, required=True)
    is_public = forms.BooleanField(required=False, initial=False)

class JoinGroupForm(forms.Form):
    password = forms.CharField(widget=forms.PasswordInput)

class GroupMessageForm(forms.Form):
    message = forms.CharField(widget=forms.Textarea, required=False)
    file = forms.FileField(required=False)

def check_bsm_agreement():
    """Check if BSM A2A agreement has been accepted"""
    global BSM_ENABLED
    try:
        if os.path.exists(A2A_FILE):
            with open(A2A_FILE, 'r', encoding="UTF-8") as f:
                content = f.read().strip()
                BSM_ENABLED = content == '1'
        return BSM_ENABLED
    except:
        return False
def get_bsm_agreement_content():
    """Return the full BSM A2A agreement content"""
    return """BSM A2A (AGREE TO ALL) AGREEMENT

BETWEEN SERVER MESSAGING (BSM) SERVICE TERMS AND CONDITIONS

Last Updated: {date}

1. ACCEPTANCE OF TERMS
By setting the A2A variable to 1 in this agreement file, you hereby agree to all terms and conditions contained in this BSM A2A (Agree To All) Agreement. This constitutes a legally binding agreement between you (the "User") and the BEAM Chat Service.

2. SERVICE DESCRIPTION
The BSM (Between Server Messaging) service enables cross-server communication between BEAM Chat instances. This includes:
- Sending messages to users on other BEAM servers
- Receiving messages from users on other BEAM servers
- Server-to-server validation of message delivery
- User discovery across the BEAM network

3. USER RESPONSIBILITIES
3.1 You agree to use BSM services only for lawful purposes and in accordance with this agreement.
3.2 You are responsible for all content transmitted through your account via BSM.
3.3 You agree not to use BSM for:
   - Spamming or unsolicited bulk messaging
   - Harassment, threats, or abusive behavior
   - Distribution of malicious software
   - Transmission of illegal content
   - Impersonation of other users or entities

4. PRIVACY AND DATA HANDLING
4.1 Message Content: BSM messages are encrypted during transmission but may be stored in plaintext on receiving servers.
4.2 Metadata: The following metadata may be transmitted with BSM messages:
   - Sender username and server
   - Recipient beam number
   - Timestamp
   - Message validation status
4.3 Cross-Server Data: By using BSM, you acknowledge that your messages and metadata may be stored on servers outside your control.

5. SERVER OPERATOR OBLIGATIONS
5.1 As a server operator enabling BSM, you agree to:
   - Maintain reasonable security measures
   - Respect the privacy of users
   - Process validation requests in good faith
   - Not intentionally interfere with message delivery

6. INTELLECTUAL PROPERTY
6.1 You retain rights to the content you create and transmit via BSM.
6.2 The BSM protocol and infrastructure remain the property of the BEAM Chat project.

7. DISCLAIMER OF WARRANTIES
THE BSM SERVICE IS PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO:
- Reliability of message delivery
- Uptime or availability of the service
- Security of transmitted data
- Accuracy of message validation

8. LIMITATION OF LIABILITY
TO THE FULLEST EXTENT PERMITTED BY LAW, THE BEAM CHAT PROJECT AND SERVER OPERATORS SHALL NOT BE LIABLE FOR:
- Lost, delayed, or undelivered messages
- Unauthorized access to message content
- Damages resulting from service interruption
- Consequences of cross-server communication

9. MESSAGE RETENTION
9.1 BSM messages may be stored indefinitely on receiving servers.
9.2 Server operators may implement their own retention policies.
9.3 Users should not rely on BSM for permanent message storage.

10. SERVICE MODIFICATIONS
10.1 The BSM protocol may be updated without prior notice.
10.2 Server operators may disable BSM functionality at their discretion.
10.3 Compatibility between different BSM versions is not guaranteed.

11. TERMINATION
11.1 Server operators may terminate BSM access for users violating this agreement.
11.2 The BSM service may be discontinued entirely with reasonable notice.

12. CROSS-JURISDICTIONAL COMPLIANCE
12.1 You acknowledge that BSM messages may cross international boundaries.
12.2 You are responsible for compliance with local laws regarding electronic communications.

13. INDEMNIFICATION
You agree to indemnify and hold harmless the BEAM Chat project, server operators, and contributors from any claims, damages, or losses resulting from your use of BSM services.

14. GOVERNING LAW
This agreement shall be governed by the laws of the jurisdiction where the BEAM server is operated, or if not specified, by international internet communication standards.

15. ENTIRE AGREEMENT
This BSM A2A constitutes the entire agreement between you and the BEAM Chat service regarding BSM functionality and supersedes all prior communications.

16. ACCEPTANCE
By setting A2A=1, you acknowledge that:
- You have read and understood this agreement
- You agree to be bound by all terms and conditions
- You are authorized to accept these terms on behalf of yourself and your organization
- This action constitutes your electronic signature

ACCEPTANCE: A2A=1

DECLINE: A2A=0

Your current status: {status}

To accept these terms and enable BSM functionality:
1. Create a file named 'bsm.a2a' in the server directory
2. Write '1' in the file and save it
3. Restart the server

To decline, set A2A to 0 or delete the file.
""".format(
        date=datetime.now().strftime('%Y-%m-%d'),
        status="ACCEPTED" if check_bsm_agreement() else "NOT ACCEPTED"
    )

def create_bsm_agreement_file():
    agreement_content = get_bsm_agreement_content()
    
    with open('bsm_agreement.txt', 'w', encoding='utf-8') as f:
        f.write(agreement_content)
    
    print("BSM A2A agreement file created: bsm_agreement.txt")

def create_group(name, description, password, emoji_picture, created_by, is_public=False):
    """Create a new group"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if group name already exists
            cursor.execute('SELECT id FROM groups WHERE name = ?', (name,))
            if cursor.fetchone():
                return False, "Group name already exists"
            
            # Create group
            encrypted_name = encrypt_data(name)
            encrypted_description = encrypt_data(description) if description else None
            encrypted_emoji = encrypt_data(emoji_picture)
            
            cursor.execute('''
                INSERT INTO groups (name, description, password_hash, emoji_picture, created_by, created_at, is_public)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                encrypted_name,
                encrypted_description,
                hash_password(password),
                encrypted_emoji,
                created_by,
                encrypt_data(datetime.now().isoformat()),
                1 if is_public else 0
            ))
            
            group_id = cursor.lastrowid
            
            # Add creator as admin
            cursor.execute('''
                INSERT INTO group_members (group_id, username, joined_at, role)
                VALUES (?, ?, ?, ?)
            ''', (
                group_id,
                created_by,
                datetime.now().isoformat(),
                'admin'
            ))
            
            conn.commit()
            return True, f"Group '{name}' created successfully"
            
    except sqlite3.Error as e:
        return False, f"Database error: {str(e)}"

def get_group(group_id):
    """Get group information with decrypted data"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM groups WHERE id = ?', (group_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
                
            group_data = dict(row)
            
            # Decrypt sensitive fields
            if group_data.get('name'):
                group_data['name'] = decrypt_data(group_data['name'])
            if group_data.get('description'):
                group_data['description'] = decrypt_data(group_data['description'])
            if group_data.get('emoji_picture'):
                group_data['emoji_picture'] = decrypt_data(group_data['emoji_picture'])
            if group_data.get('created_at'):
                group_data['created_at'] = decrypt_data(group_data['created_at'])
                
            return group_data
    except Exception as e:
        print(f"Error decrypting group data: {e}")
        return None

def get_user_groups(username):
    """Get all groups that a user is member of"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT g.*, gm.role 
                FROM groups g
                JOIN group_members gm ON g.id = gm.group_id
                WHERE gm.username = ?
                ORDER BY g.created_at DESC
            ''', (username,))
            
            groups = []
            for row in cursor.fetchall():
                group_data = dict(row)
                
                # Decrypt sensitive fields
                if group_data.get('name'):
                    group_data['name'] = decrypt_data(group_data['name'])
                if group_data.get('description'):
                    group_data['description'] = decrypt_data(group_data['description'])
                if group_data.get('emoji_picture'):
                    group_data['emoji_picture'] = decrypt_data(group_data['emoji_picture'])
                if group_data.get('created_at'):
                    group_data['created_at'] = decrypt_data(group_data['created_at'])
                    
                groups.append(group_data)
                
            return groups
    except Exception as e:
        print(f"Error getting user groups: {e}")
        return []

def join_group(group_id, username, password):
    """Join a group with password verification"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get group and verify password
            cursor.execute('SELECT * FROM groups WHERE id = ?', (group_id,))
            group_row = cursor.fetchone()
            
            if not group_row:
                return False, "Group not found"
                
            group_data = dict(group_row)
            
            if not verify_password(group_data['password_hash'], password):
                return False, "Invalid password"
            
            # Check if user is already a member
            cursor.execute('''
                SELECT id FROM group_members 
                WHERE group_id = ? AND username = ?
            ''', (group_id, username))
            
            if cursor.fetchone():
                return False, "Already a member of this group"
            
            # Add user to group
            cursor.execute('''
                INSERT INTO group_members (group_id, username, joined_at, role)
                VALUES (?, ?, ?, ?)
            ''', (
                group_id,
                username,
                datetime.now().isoformat(),
                'member'
            ))
            
            conn.commit()
            return True, "Successfully joined group"
            
    except sqlite3.Error as e:
        return False, f"Database error: {str(e)}"

def is_group_member(group_id, username):
    """Check if user is member of a group"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id FROM group_members 
                WHERE group_id = ? AND username = ?
            ''', (group_id, username))
            return cursor.fetchone() is not None
    except sqlite3.Error:
        return False

def get_group_members(group_id):
    """Get all members of a group"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT u.username, gm.role, gm.joined_at, u.profile_picture
                FROM group_members gm
                JOIN users u ON gm.username = u.username
                WHERE gm.group_id = ?
                ORDER BY 
                    CASE gm.role 
                        WHEN 'admin' THEN 1
                        ELSE 2 
                    END,
                    gm.joined_at
            ''', (group_id,))
            
            members = []
            for row in cursor.fetchall():
                member_data = dict(row)
                if member_data.get('profile_picture'):
                    member_data['profile_picture'] = decrypt_data(member_data['profile_picture'])
                members.append(member_data)
                
            return members
    except Exception as e:
        print(f"Error getting group members: {e}")
        return []

def save_group_message(group_id, username, message, filename=None, file_url=None):
    """Save group message to database"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Encrypt message content
            encrypted_message = encrypt_data(message)
            encrypted_timestamp = encrypt_data(timestamp)
            encrypted_filename = encrypt_data(filename) if filename else None
            encrypted_file_url = encrypt_data(file_url) if file_url else None
            
            cursor.execute('''
                INSERT INTO group_messages (group_id, username, message, timestamp, filename, file_url)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                group_id,
                username,
                encrypted_message,
                encrypted_timestamp,
                encrypted_filename,
                encrypted_file_url
            ))
            
            conn.commit()
            
            # Return decrypted message for immediate use
            return {
                'group_id': group_id,
                'username': username,
                'message': message,
                'timestamp': timestamp,
                'filename': filename,
                'file_url': file_url
            }
            
    except sqlite3.Error as e:
        print(f"Database error saving group message: {e}")
        return None

def read_group_messages(group_id):
    """Read group messages from database with decrypted content"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT username, message, timestamp, filename, file_url
                FROM group_messages 
                WHERE group_id = ?
                ORDER BY timestamp
            ''', (group_id,))
            
            messages = []
            for row in cursor.fetchall():
                message_data = dict(row)
                
                # Decrypt all encrypted fields
                if message_data.get('message'):
                    message_data['message'] = decrypt_data(message_data['message'])
                if message_data.get('timestamp'):
                    message_data['timestamp'] = decrypt_data(message_data['timestamp'])
                if message_data.get('filename'):
                    message_data['filename'] = decrypt_data(message_data['filename'])
                if message_data.get('file_url'):
                    message_data['file_url'] = decrypt_data(message_data['file_url'])
                
                messages.append(message_data)
                
            return messages
    except Exception as e:
        print(f"Error decrypting group messages: {e}")
        return []

def get_public_groups():
    """Get all public groups"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM groups WHERE is_public = 1 ORDER BY created_at DESC')
            
            groups = []
            for row in cursor.fetchall():
                group_data = dict(row)
                
                # Decrypt sensitive fields
                if group_data.get('name'):
                    group_data['name'] = decrypt_data(group_data['name'])
                if group_data.get('description'):
                    group_data['description'] = decrypt_data(group_data['description'])
                if group_data.get('emoji_picture'):
                    group_data['emoji_picture'] = decrypt_data(group_data['emoji_picture'])
                if group_data.get('created_at'):
                    group_data['created_at'] = decrypt_data(group_data['created_at'])
                    
                # Get member count
                cursor.execute('SELECT COUNT(*) FROM group_members WHERE group_id = ?', (group_data['id'],))
                group_data['member_count'] = cursor.fetchone()[0]
                
                groups.append(group_data)
                
            return groups
    except Exception as e:
        print(f"Error getting public groups: {e}")
        return []


# User management functions
def hash_password(password, salt=None):
    """Hash a password with a salt using PBKDF2"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    hashed = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return f"{base64.b64encode(salt).decode('utf-8')}${hashed.decode('utf-8')}"

def verify_password(stored_password, provided_password):
    """Verify a password against a stored hash"""
    try:
        salt_b64, hashed = stored_password.split('$')
        salt = base64.b64decode(salt_b64)
        
        new_hash = hash_password(provided_password, salt)
        return hmac.compare_digest(stored_password, new_hash)
    except:
        return False
    
def read_bsm_messages():
    """Read BSM messages from database with decrypted content"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM bsm_messages ORDER BY timestamp')
            
            decrypted_messages = []
            for row in cursor.fetchall():
                message_data = dict(row)
                
                # Decrypt all encrypted fields
                if message_data.get('sender'):
                    message_data['sender'] = decrypt_data(message_data['sender'])
                if message_data.get('sender_server'):
                    message_data['sender_server'] = decrypt_data(message_data['sender_server'])
                if message_data.get('recipient_beam_number'):
                    message_data['recipient_beam_number'] = decrypt_data(message_data['recipient_beam_number'])
                if message_data.get('recipient_local_number'):
                    message_data['recipient_local_number'] = decrypt_data(message_data['recipient_local_number'])
                if message_data.get('message'):
                    message_data['message'] = decrypt_data(message_data['message'])
                if message_data.get('timestamp'):
                    message_data['timestamp'] = decrypt_data(message_data['timestamp'])
                    
                decrypted_messages.append(message_data)
                
            return decrypted_messages
    except Exception as e:
        print(f"Error decrypting BSM messages: {e}")
        return []


def save_bsm_messages(messages):
    """Save BSM messages to database with encrypted content"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Clear existing messages (for compatibility with old code)
            cursor.execute('DELETE FROM bsm_messages')
            
            # Insert all messages with encrypted data
            for msg in messages:
                # Encrypt all sensitive fields
                encrypted_sender = encrypt_data(msg.get('sender', ''))
                encrypted_sender_server = encrypt_data(msg.get('sender_server', ''))
                encrypted_recipient_beam_number = encrypt_data(msg.get('recipient_beam_number', ''))
                encrypted_recipient_local_number = encrypt_data(msg.get('recipient_local_number', ''))
                encrypted_message = encrypt_data(msg.get('message', ''))
                encrypted_timestamp = encrypt_data(msg.get('timestamp', ''))
                
                cursor.execute('''
                    INSERT INTO bsm_messages 
                    (message_id, sender, sender_server, recipient_beam_number, 
                     recipient_local_number, message, timestamp, status, validation_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    msg.get('message_id', generate_message_id()),
                    encrypted_sender,
                    encrypted_sender_server,
                    encrypted_recipient_beam_number,
                    encrypted_recipient_local_number,
                    encrypted_message,
                    encrypted_timestamp,
                    msg.get('status', 'sent'),
                    msg.get('validation_status', 'pending')
                ))
            
            conn.commit()
            print(f"Saved {len(messages)} BSM messages to database")
            
    except Exception as e:
        print(f"Error saving BSM messages: {e}")

def parse_beam_number(beam_number):
    """
    Parse beam number format: +server_ip xxx-xxx-xxx
    Returns: (server_url, local_number) or (None, None) if invalid
    """
    try:
        if not beam_number.startswith('+'):
            return None, None
        
        parts = beam_number[1:].split(' ', 1)
        if len(parts) != 2:
            return None, None
        
        server_part, number_part = parts
        
        # Validate number format (xxx-xxx-xxx)
        if not all(part.isdigit() for part in number_part.split('-')):
            return None, None
        
        # Different server - assume HTTP if not specified
        server_url = server_part
        if not server_url.startswith(('http://', 'https://')):
            server_url = f"http://{server_url}"
        
        # Validate URL format
        parsed = urlparse(server_url)
        if not parsed.netloc:
            return None, None
            
        return server_url, number_part
        
    except Exception:
        return None, None


def generate_message_id():
    """Generate unique message ID"""
    return str(uuid.uuid4())

def send_bsm_message(sender, recipient_beam_number, message_text, sender_server_url=None):
    """Send BSM message to recipient with encrypted content"""
    recipient_server_url, recipient_local_number = parse_beam_number(recipient_beam_number)
    
    if not recipient_local_number:
        return False, None, "Invalid beam number format"
    
    message_id = generate_message_id()
    timestamp = datetime.now().isoformat()
    
    # Encrypt sensitive data
    encrypted_sender = encrypt_data(sender)
    encrypted_recipient_beam_number = encrypt_data(recipient_beam_number)
    encrypted_recipient_local_number = encrypt_data(recipient_local_number)
    encrypted_message_text = encrypt_data(message_text)
    encrypted_timestamp = encrypt_data(timestamp)
    encrypted_sender_server = encrypt_data(sender_server_url) if sender_server_url else None
    
    # Create message object with encrypted data
    message_data = {
        'message_id': message_id,
        'sender': encrypted_sender,
        'sender_server': encrypted_sender_server,
        'recipient_beam_number': encrypted_recipient_beam_number,
        'recipient_local_number': encrypted_recipient_local_number,
        'message': encrypted_message_text,
        'timestamp': encrypted_timestamp,
        'status': 'sent',
        'validation_status': 'pending'
    }
    
    # Save encrypted message to database
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO bsm_messages 
                (message_id, sender, sender_server, recipient_beam_number, 
                 recipient_local_number, message, timestamp, status, validation_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                message_data['message_id'],
                message_data['sender'],
                message_data['sender_server'],
                message_data['recipient_beam_number'],
                message_data['recipient_local_number'],
                message_data['message'],
                message_data['timestamp'],
                message_data['status'],
                message_data['validation_status']
            ))
            conn.commit()
            
        return True, message_id, "Message prepared for delivery via frontend"
        
    except sqlite3.Error as e:
        return False, None, f"Database error: {str(e)}"
def update_message_status(message_id, status, validation_status=None):
    """Update message status in database"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            if validation_status:
                cursor.execute('''
                    UPDATE bsm_messages 
                    SET status = ?, validation_status = ?
                    WHERE message_id = ?
                ''', (status, validation_status, message_id))
            else:
                cursor.execute(
                    'UPDATE bsm_messages SET status = ? WHERE message_id = ?',
                    (status, message_id)
                )
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database error updating message status: {e}")

def validate_message_delivery(message_id, recipient_server_url):
    """Validate that message was properly received by recipient server"""
    try:
        # Wait a moment for the recipient server to process the message
        time.sleep(2)
        
        # Request validation from recipient server
        response = requests.get(
            f"{recipient_server_url}/bsm/validate/{message_id}",
            timeout=BSM_VALIDATION_TIMEOUT
        )
        
        if response.status_code == 200:
            validation_data = response.json()
            
            if validation_data.get('valid') and validation_data.get('message_id') == message_id:
                update_message_status(message_id, 'delivered', 'validated')
            else:
                update_message_status(message_id, 'delivered', 'validation_failed: invalid_response')
        else:
            update_message_status(message_id, 'delivered', f'validation_failed: http_{response.status_code}')
            
    except requests.exceptions.RequestException as e:
        update_message_status(message_id, 'delivered', f'validation_failed: {str(e)}')


def get_message_by_id(message_id):
    """Get message by ID from database with decrypted content"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM bsm_messages WHERE message_id = ?', (message_id,))
            row = cursor.fetchone()
            
            if not row:
                return None
                
            message_data = dict(row)
            
            # Decrypt all encrypted fields
            if message_data.get('sender'):
                message_data['sender'] = decrypt_data(message_data['sender'])
            if message_data.get('sender_server'):
                message_data['sender_server'] = decrypt_data(message_data['sender_server'])
            if message_data.get('recipient_beam_number'):
                message_data['recipient_beam_number'] = decrypt_data(message_data['recipient_beam_number'])
            if message_data.get('recipient_local_number'):
                message_data['recipient_local_number'] = decrypt_data(message_data['recipient_local_number'])
            if message_data.get('message'):
                message_data['message'] = decrypt_data(message_data['message'])
            if message_data.get('timestamp'):
                message_data['timestamp'] = decrypt_data(message_data['timestamp'])
                
            return message_data
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return None

def get_user_bsm_messages(username):
    """Get all BSM messages for a user from database with decrypted content"""
    user_beam_number = get_user_beam_number(username)
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get encrypted messages from database
            cursor.execute('''
                SELECT * FROM bsm_messages 
                ORDER BY timestamp DESC
            ''')
            
            decrypted_messages = []
            for row in cursor.fetchall():
                message_data = dict(row)
                
                # Decrypt all fields
                if message_data.get('sender'):
                    message_data['sender'] = decrypt_data(message_data['sender'])
                if message_data.get('sender_server'):
                    message_data['sender_server'] = decrypt_data(message_data['sender_server'])
                if message_data.get('recipient_beam_number'):
                    message_data['recipient_beam_number'] = decrypt_data(message_data['recipient_beam_number'])
                if message_data.get('recipient_local_number'):
                    message_data['recipient_local_number'] = decrypt_data(message_data['recipient_local_number'])
                if message_data.get('message'):
                    message_data['message'] = decrypt_data(message_data['message'])
                if message_data.get('timestamp'):
                    message_data['timestamp'] = decrypt_data(message_data['timestamp'])
                
                # Filter for current user after decryption
                if message_data['sender'] == username or message_data.get('recipient_local_number') == user_beam_number:
                    decrypted_messages.append(message_data)
                    
            return decrypted_messages
    except Exception as e:
        print(f"Error decrypting BSM messages: {e}")
        return []
    
def ban_user(username, reason="Violation of terms of service"):
    """Ban a user from the system"""
    if is_user_admin(username):
        return False
        
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users 
                SET banned = 1, ban_reason = ?, banned_at = ?
                WHERE username = ?
            ''', (reason, datetime.now().isoformat(), username))
            
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error:
        return False

def unban_user(username):
    """Unban a user"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET banned = 0 WHERE username = ?',
                (username,)
            )
            conn.commit()
            return cursor.rowcount > 0
    except sqlite3.Error:
        return False

def is_user_banned(username):
    """Check if a user is banned"""
    user = get_user(username)
    return user.get('banned', False) if user else False

def get_banned_users():
    """Get list of all banned users"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT username, ban_reason, banned_at, created_at 
                FROM users 
                WHERE banned = 1
            ''')
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error:
        return []

def get_all_users():
    """Get list of all users with their status"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT username, banned, ban_reason, banned_at, created_at, last_login
                FROM users
            ''')
            return [dict(row) for row in cursor.fetchall()]
    except sqlite3.Error:
        return []

def read_users():
    """Read all users from database with decrypted data"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users')
        users = {}
        for row in cursor.fetchall():
            user_data = dict(row)
            
            # Decrypt sensitive fields for each user
            if user_data.get('beam_number'):
                user_data['beam_number'] = decrypt_data(user_data['beam_number'])
            if user_data.get('profile_picture'):
                user_data['profile_picture'] = decrypt_data(user_data['profile_picture'])
            if user_data.get('created_at'):
                user_data['created_at'] = decrypt_data(user_data['created_at'])
            if user_data.get('last_login'):
                user_data['last_login'] = decrypt_data(user_data['last_login'])
            if user_data.get('banned_at'):
                user_data['banned_at'] = decrypt_data(user_data['banned_at'])
                
            users[user_data['username']] = user_data
        return users
    

def save_users(users):
    """Save users to database - Note: This function may not be needed with direct DB operations"""
    # This function is kept for compatibility but most operations should be direct DB calls
    pass

def generate_unique_beam_number():
    """Generate a unique beam number using database"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            while True:
                part1 = ''.join(random.choices('0123456789', k=3))
                part2 = ''.join(random.choices('0123456789', k=3))
                part3 = ''.join(random.choices('0123456789', k=3))
                beam_number = f"{part1}-{part2}-{part3}"
                
                # Check if this number is already assigned in database
                cursor.execute(
                    'SELECT username FROM users WHERE beam_number = ?',
                    (beam_number,)
                )
                if not cursor.fetchone():
                    return beam_number
                    
    except sqlite3.Error:
        # Fallback to old method if database fails
        users = read_users()
        while True:
            part1 = ''.join(random.choices('0123456789', k=3))
            part2 = ''.join(random.choices('0123456789', k=3))
            part3 = ''.join(random.choices('0123456789', k=3))
            beam_number = f"{part1}-{part2}-{part3}"
            
            number_exists = any(
                user_data.get('beam_number') == beam_number 
                for user_data in users.values()
            )
            
            if not number_exists:
                return beam_number

def create_user(username, password):
    """Create a new user in database with encrypted data"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Check if user already exists
            cursor.execute('SELECT username FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                return False, "Username already exists"
            
            # Generate beam number and profile picture
            beam_number = generate_unique_beam_number()
            profile_pic_filename = generate_default_profile_picture(username)
            
            # Encrypt sensitive data
            encrypted_beam_number = encrypt_data(beam_number) if beam_number else None
            encrypted_profile_picture = encrypt_data(profile_pic_filename) if profile_pic_filename else None
            
            # Insert new user with encrypted data
            cursor.execute('''
                INSERT INTO users (username, password_hash, beam_number, profile_picture, created_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                username,
                hash_password(password),  # Password is already hashed, no need to encrypt
                encrypted_beam_number,
                encrypted_profile_picture,
                encrypt_data(datetime.now().isoformat())  # Encrypt timestamp
            ))
            
            conn.commit()
            return True, "User created successfully"
            
    except sqlite3.Error as e:
        return False, f"Database error: {str(e)}"

def authenticate_user(username, password):
    """Authenticate a user against database"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM users WHERE username = ?', 
                (username,)
            )
            user_row = cursor.fetchone()
            
            if not user_row:
                return False, "User not found"
            
            user = dict(user_row)
            
            # Check if user is banned
            if user.get('banned'):
                ban_reason = user.get('ban_reason', 'Violation of terms of service')
                return False, f"Account banned: {ban_reason}"
            
            if not verify_password(user['password_hash'], password):
                return False, "Invalid password"
            
            # Update last login
            cursor.execute(
                'UPDATE users SET last_login = ? WHERE username = ?',
                (datetime.now().isoformat(), username)
            )
            conn.commit()
            
            return True, "Authentication successful"
            
    except sqlite3.Error as e:
        return False, f"Database error: {str(e)}"


def get_user(username):
    """Get user information from database with decrypted data"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            row = cursor.fetchone()
            
            if not row:
                return None
                
            user_data = dict(row)
            
            # Decrypt sensitive fields
            if user_data.get('beam_number'):
                user_data['beam_number'] = decrypt_data(user_data['beam_number'])
            if user_data.get('profile_picture'):
                user_data['profile_picture'] = decrypt_data(user_data['profile_picture'])
            if user_data.get('created_at'):
                user_data['created_at'] = decrypt_data(user_data['created_at'])
            if user_data.get('last_login'):
                user_data['last_login'] = decrypt_data(user_data['last_login'])
            if user_data.get('banned_at'):
                user_data['banned_at'] = decrypt_data(user_data['banned_at'])
                
            return user_data
    except Exception as e:
        print(f"Error decrypting user data: {e}")
        return None


def update_user_profile_picture(username, profile_picture_filename):
    """Update user's profile picture in database with encrypted data"""
    try:
        encrypted_filename = encrypt_data(profile_picture_filename) if profile_picture_filename else None
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'UPDATE users SET profile_picture = ? WHERE username = ?',
                (encrypted_filename, username)
            )
            conn.commit()
            return True
    except sqlite3.Error:
        return False

def generate_default_profile_picture(username, size=200):
    """Generate a GitHub-style default profile picture"""
    # Define colors for the background (similar to GitHub's color palette)
    colors = [
        (40, 167, 69),   # Green
        (0, 123, 255),   # Blue
        (111, 66, 193),  # Purple
        (220, 53, 69),   # Red
        (253, 126, 20),  # Orange
        (32, 201, 151),  # Teal
        (108, 117, 125), # Gray
    ]
    
    # Select a color based on the username
    color_index = hash(username) % len(colors)
    bg_color = colors[color_index]
    
    # Create image with white background
    img = Image.new('RGB', (size, size), color=bg_color)
    draw = ImageDraw.Draw(img)
    
    # Get the first letter of the username (or first two if available)
    initials = username[:2].upper() if len(username) >= 2 else username[0].upper()
    
    # Try to load a font, fall back to default if not available
    try:
        font = ImageFont.truetype("arial.ttf", size=size//2)
    except:
        # Use default font
        font = ImageFont.load_default()
    
    # Calculate text size and position
    bbox = draw.textbbox((0, 0), initials, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    
    x = (size - text_width) / 2
    y = (size - text_height) / 2.5
    
    # Draw the text
    draw.text((x, y), initials, fill=(255, 255, 255), font=font)
    
    # Save the image
    filename = f"{username}_default_{uuid.uuid4().hex[:8]}.png"
    filepath = os.path.join(PROFILE_PICS_DIR, filename)
    img.save(filepath, 'PNG')
    
    return filename

def save_profile_picture(uploaded_file, username):
    """Save an uploaded profile picture and remove the old one"""
    user = get_user(username)
    old_filename = user.get('profile_picture') if user else None
    
    # Generate a unique filename
    file_ext = os.path.splitext(uploaded_file.name)[1].lower()
    if file_ext not in ['.jpg', '.jpeg', '.png', '.gif']:
        file_ext = '.png'  # Default to png if invalid extension
    
    filename = f"{username}_profile_{uuid.uuid4().hex[:8]}{file_ext}"
    filepath = os.path.join(PROFILE_PICS_DIR, filename)
    
    # Save the new file
    with open(filepath, 'wb+') as destination:
        for chunk in uploaded_file.chunks():
            destination.write(chunk)
    
    # Remove the old profile picture if it exists and is not a default one
    if old_filename:
        # Check if it's a default profile picture (either old format or new format)
        is_default = (
            old_filename.startswith(f"{username}_default_") or 
            "default" in old_filename.lower()
        )
        
        if not is_default:
            old_filepath = os.path.join(PROFILE_PICS_DIR, old_filename)
            try:
                if os.path.exists(old_filepath):
                    os.remove(old_filepath)
                    print(f"Removed old profile picture: {old_filename}")
            except OSError as e:
                print(f"Error removing old profile picture {old_filename}: {e}")
    
    # Update user's profile picture in the database
    update_user_profile_picture(username, filename)
    
    return filename

def get_profile_picture_url(username):
    """Get the URL for a user's profile picture"""
    user = get_user(username)
    if user and 'profile_picture' in user and user['profile_picture']:
        return f"/profile_pic/{user['profile_picture']}"
    else:
        # Generate a default one if it doesn't exist
        profile_pic_filename = generate_default_profile_picture(username)
        update_user_profile_picture(username, profile_pic_filename)
        return f"/profile_pic/{profile_pic_filename}"

# Session management
def create_session(response, username):
    """Create a session for the user"""
    session_id = str(uuid.uuid4())
    session_data = {
        'username': username,
        'created_at': datetime.now().isoformat()
    }
    
    # In a real application, we'd store this in a database
    # For simplicity, we'll just set a cookie with encrypted data
    encrypted_session = encrypt_data(json.dumps(session_data))
    response.set_cookie(SESSION_COOKIE_NAME, encrypted_session, max_age=3600*24*7)  # 1 week
    return response

def get_session(request):
    """Get session data from request"""
    session_cookie = request.COOKIES.get(SESSION_COOKIE_NAME)
    if not session_cookie:
        return None
    
    try:
        session_data = json.loads(decrypt_data(session_cookie))
        return session_data
    except:
        return None

def logout_user(response):
    """Log out user by clearing session cookie"""
    response.delete_cookie(SESSION_COOKIE_NAME)
    return response

# Utility functions
def read_chat_messages():
    """Read chat messages from database with decrypted content"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT username, message, timestamp, filename, file_url, 
                       is_private, target_user
                FROM chat_messages 
                ORDER BY timestamp
            ''')
            
            messages = []
            for row in cursor.fetchall():
                message_data = dict(row)
                
                # Decrypt all encrypted fields
                if message_data.get('message'):
                    message_data['message'] = decrypt_data(message_data['message'])
                if message_data.get('timestamp'):
                    message_data['timestamp'] = decrypt_data(message_data['timestamp'])
                if message_data.get('filename'):
                    message_data['filename'] = decrypt_data(message_data['filename'])
                if message_data.get('file_url'):
                    message_data['file_url'] = decrypt_data(message_data['file_url'])
                if message_data.get('target_user'):
                    message_data['target_user'] = decrypt_data(message_data['target_user'])
                
                # Convert boolean values
                message_data['is_private'] = bool(message_data['is_private'])
                messages.append(message_data)
                
            return messages
    except sqlite3.Error as e:
        print(f"Database error reading messages: {e}")
        return []
    except Exception as e:
        print(f"Error decrypting messages: {e}")
        return []

def handle_private_message(message_text):
    """
    Handle private messages using m/username/message syntax.
    """
    if message_text.startswith('m/') and '/' in message_text[2:]:
        parts = message_text[2:].split('/', 1)
        
        if len(parts) >= 2:
            target_username = parts[0]
            private_message = parts[1]
            return target_username, private_message
    
    return None, None

def handle_message_edit(message_text):
    """
    Handle message editing using s/<old_word>/<new_word> syntax.
    Only replaces the first occurrence of old_word with new_word.
    """
    if message_text.startswith('s/') and '/' in message_text[2:]:
        # Extract the parts after 's/'
        parts = message_text[2:].split('/', 2)
        
        if len(parts) >= 2:
            old_word = parts[0]
            new_word = parts[1]
            
            # If there's a trailing slash with nothing after it, treat as empty replacement
            if len(parts) == 3 and parts[2] == '':
                # This handles the case of s/word// to delete a word
                pass
            elif len(parts) == 2:
                # This is a valid s/old/new pattern
                return old_word, new_word
    
    return None, None

def handle_message_edit_in_db(username, old_word, new_word, timestamp):
    """Handle message editing in database with encrypted content"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Get user's last message
            cursor.execute('''
                SELECT id, message FROM chat_messages 
                WHERE username = ? 
                ORDER BY timestamp DESC 
                LIMIT 1
            ''', (username,))
            
            result = cursor.fetchone()
            if not result:
                return {
                    'username': username,
                    'message': f"(edit failed) s/{old_word}/{new_word}",
                    'timestamp': timestamp
                }
            
            message_id, encrypted_original_text = result['id'], result['message']
            
            # Decrypt the original message
            original_text = decrypt_data(encrypted_original_text)
            
            # Replace only the first occurrence
            if old_word in original_text:
                edited_text = original_text.replace(old_word, new_word, 1)
                
                # Encrypt and update the message in database
                encrypted_edited_text = encrypt_data(edited_text)
                cursor.execute(
                    'UPDATE chat_messages SET message = ? WHERE id = ?',
                    (encrypted_edited_text, message_id)
                )
                conn.commit()
                
                return {
                    'username': username,
                    'message': f"{edited_text} (edited)",
                    'timestamp': timestamp
                }
            else:
                return {
                    'username': username,
                    'message': f"(edit failed) s/{old_word}/{new_word}",
                    'timestamp': timestamp
                }
                
    except sqlite3.Error as e:
        print(f"Database error editing message: {e}")
        return {
            'username': username,
            'message': f"(edit failed) s/{old_word}/{new_word}",
            'timestamp': timestamp
        }

def save_chat_message(username, message, filename=None, file_url=None):
    """Save chat message to database with encrypted content"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Handle message editing (s/old/new syntax)
    old_word, new_word = handle_message_edit(message)
    if old_word is not None:
        return handle_message_edit_in_db(username, old_word, new_word, timestamp)
    
    # Handle private messages (m/user/message syntax)
    target_username, private_message = handle_private_message(message)
    is_private = target_username is not None
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Encrypt message content and timestamp
            encrypted_timestamp = encrypt_data(timestamp)
            encrypted_filename = encrypt_data(filename) if filename else None
            encrypted_file_url = encrypt_data(file_url) if file_url else None
            
            if is_private:
                # Encrypt private message
                encrypted_message = encrypt_data(f"(to {target_username}) {private_message}")
                encrypted_target_user = encrypt_data(target_username)
                
                cursor.execute('''
                    INSERT INTO chat_messages 
                    (username, message, timestamp, filename, file_url, is_private, target_user)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    username,
                    encrypted_message,
                    encrypted_timestamp,
                    encrypted_filename,
                    encrypted_file_url,
                    1,  # True
                    encrypted_target_user
                ))
                display_message = f"(to {target_username}) {private_message}"
            else:
                # Encrypt regular message
                encrypted_message = encrypt_data(message)
                
                cursor.execute('''
                    INSERT INTO chat_messages 
                    (username, message, timestamp, filename, file_url, is_private)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    username,
                    encrypted_message,
                    encrypted_timestamp,
                    encrypted_filename,
                    encrypted_file_url,
                    0  # False
                ))
                display_message = message
            
            conn.commit()
            
            # Return decrypted message data for immediate use
            return {
                'username': username,
                'message': display_message,
                'timestamp': timestamp,
                'filename': filename,
                'file_url': file_url,
                'is_private': is_private,
                'target_user': target_username
            }
            
    except sqlite3.Error as e:
        print(f"Database error saving message: {e}")
        return None

def get_user_beam_number(username):
    """Get the beam number for a user"""
    users = read_users()
    
    if username not in users:
        return None
    
    return users[username].get('beam_number')

def get_full_beam_number(username):
    """Get full beam number with server prefix"""
    beam_number = get_user_beam_number(username)
    if beam_number:
        return beam_number
    return None

def read_bulletin():
    """Read bulletin content from database with decrypted content"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT content FROM bulletin_board ORDER BY id DESC LIMIT 1')
            row = cursor.fetchone()
            
            if row and row['content']:
                # Decrypt the bulletin content
                return decrypt_data(row['content'])
            else:
                return "Bulletin board is empty."
    except Exception as e:
        print(f"Error decrypting bulletin: {e}")
        return "Bulletin board is empty."

def write_bulletin(content):
    """Write bulletin content to database with encrypted content"""
    try:
        encrypted_content = encrypt_data(content)
        
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO bulletin_board (content, updated_at) VALUES (?, ?)',
                (encrypted_content, encrypt_data(datetime.now().isoformat()))
            )
            conn.commit()
        return content
    except Exception as e:
        print(f"Error encrypting bulletin: {e}")
        return "Error updating bulletin board"

def save_uploaded_file(uploaded_file):
    # Генерируем уникальное имя файла для предотвращения конфликтов
    file_ext = os.path.splitext(uploaded_file.name)[1]
    filename = f"{uuid.uuid4().hex}{file_ext}"
    filepath = os.path.join(UPLOAD_DIR, filename)
    
    with open(filepath, 'wb+') as destination:
        for chunk in uploaded_file.chunks():
            destination.write(chunk)
    
    return filename, f"/download/{filename}"

def get_current_server_url(request):
    """Get the current server's URL from the request"""
    scheme = 'https' if request.is_secure() else 'http'
    host = request.get_host()
    return f"{scheme}://{host}"

# Views

@csrf_exempt
@require_http_methods(["POST"])
@csrf_exempt
@require_http_methods(["POST"])
def bsm_receive_message(request):
    """Receive BSM message from another server or frontend"""
    try:
        # Handle both JSON and form data
        if request.content_type == 'application/json':
            data = json.loads(request.body)
        else:
            # Fallback to form data
            data = {
                'sender': request.POST.get('sender'),
                'sender_server': request.POST.get('sender_server'),
                'recipient_beam_number': request.POST.get('recipient_beam_number'),
                'message': request.POST.get('message'),
                'timestamp': request.POST.get('timestamp'),
                'message_id': request.POST.get('message_id')
            }
        
        # Validate required fields
        required_fields = ['sender', 'sender_server', 'recipient_beam_number', 'message', 'timestamp']
        for field in required_fields:
            if field not in data or not data[field]:
                return JsonResponse({'error': f'Missing field: {field}'}, status=400)
        
        # Generate message ID if not provided
        message_id = data.get('message_id') or generate_message_id()
        
        # Parse recipient beam number to extract local number
        recipient_server_url, recipient_local_number = parse_beam_number(data['recipient_beam_number'])
        
        # Check if this is a local user (same server)
        is_local_user = False
        current_server_url = get_current_server_url(request)
        if recipient_server_url and recipient_local_number:
            # Check if recipient_local_number matches any user on this server
            users = read_users()
            for username, user_data in users.items():
                if user_data.get('beam_number') == recipient_local_number:
                    is_local_user = True
                    break
        
        # Save message to database
        try:
            # Encrypt sensitive data
            encrypted_sender = encrypt_data(data['sender'])
            encrypted_sender_server = encrypt_data(data['sender_server'])
            encrypted_recipient_beam_number = encrypt_data(data['recipient_beam_number'])
            encrypted_recipient_local_number = encrypt_data(recipient_local_number or '')
            encrypted_message = encrypt_data(data['message'])
            encrypted_timestamp = encrypt_data(data['timestamp'])
            
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO bsm_messages 
                    (message_id, sender, sender_server, recipient_beam_number, 
                     recipient_local_number, message, timestamp, status, validation_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    message_id,
                    encrypted_sender,
                    encrypted_sender_server,
                    encrypted_recipient_beam_number,
                    encrypted_recipient_local_number,
                    encrypted_message,
                    encrypted_timestamp,
                    'received' if is_local_user else 'sent',
                    'pending_validation'
                ))
                conn.commit()
                
            print(f"BSM message saved: {message_id} from {data['sender']} to {data['recipient_beam_number']}")
            
            # Start validation if it's from another server and we're the recipient
            if data['sender_server'] != current_server_url and is_local_user:
                threading.Thread(
                    target=validate_message_delivery,
                    args=(message_id, data['sender_server']),
                    daemon=True
                ).start()
            
            return JsonResponse({
                'status': 'received', 
                'message_id': message_id,
                'local_user': is_local_user
            })
            
        except sqlite3.Error as e:
            print(f"Database error saving BSM message: {e}")
            return JsonResponse({'error': f'Database error: {str(e)}'}, status=500)
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        print(f"Error in bsm_receive_message: {e}")
        return JsonResponse({'error': str(e)}, status=500)

@require_http_methods(["GET"])
def bsm_validate_message(request, message_id):
    """Validate message existence for sender server"""
    try:
        message = get_message_by_id(message_id)
        
        if message:
            return JsonResponse({
                'valid': True,
                'message_id': message_id,
                'sender': message['sender'],
                'recipient_beam_number': message['recipient_beam_number']
            })
        else:
            return JsonResponse({'valid': False, 'error': 'Message not found'}, status=404)
            
    except Exception as e:
        return JsonResponse({'valid': False, 'error': str(e)}, status=500)
    
def bsm_dashboard_view(request):
    """View for BSM dashboard with statistics and overview"""
    # Check if BSM is enabled
    if not check_bsm_agreement():
        return HttpResponse('BSM functionality is disabled. Administrator must accept BSM A2A agreement first by creating bsm.a2a file with content "1".', status=403)
    
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    
    # Get user's beam number
    beam_number = get_user_beam_number(username)
    
    # Remove protocol from server URL for display
    server_url = get_current_server_url(request)
    server_without_protocol = server_url.replace('http://', '').replace('https://', '')
    full_beam_number = f"+{server_without_protocol} {beam_number}" if beam_number else None
    
    profile_pic_url = get_profile_picture_url(username)
    
    # Get message statistics
    user_messages = get_user_bsm_messages(username)
    
    sent_count = len([msg for msg in user_messages if msg['sender'] == username])
    received_count = len([msg for msg in user_messages if msg['sender'] != username])
    delivered_count = len([msg for msg in user_messages if msg.get('status') == 'delivered'])
    pending_count = len([msg for msg in user_messages if msg.get('status') in ['sent', 'pending']])
    total_messages = len(user_messages)
    
    # Get recent messages (last 5)
    recent_messages = []
    for msg in user_messages[-5:][::-1]:  # Get last 5, reversed for newest first
        recent_msg = msg.copy()
        recent_msg['profile_pic_url'] = get_profile_picture_url(msg['sender']) if msg['sender'] != username else profile_pic_url
        recent_messages.append(recent_msg)
    
    # Load template from file
    template_path = "templates/bsm/bsm_dashboard.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({
        'username': username,
        'full_beam_number': full_beam_number,
        'profile_pic_url': profile_pic_url,
        'current_server': server_without_protocol,
        'sent_count': sent_count,
        'received_count': received_count,
        'delivered_count': delivered_count,
        'pending_count': pending_count,
        'total_messages': total_messages,
        'recent_messages': recent_messages
    })
    
    return HttpResponse(template.render(context))
    
def groups_list_view(request):
    """View for listing user's groups and public groups"""
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    user_groups = get_user_groups(username)
    public_groups = get_public_groups()
    
    # Load template from file
    template_path = "templates/groups/groups_list.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({
        'username': username,
        'user_groups': user_groups,
        'public_groups': public_groups
    })
    
    return HttpResponse(template.render(context))

def create_group_view(request):
    """View for creating new groups"""
    try:
        session = get_session(request)
        if not session or 'username' not in session:
            return HttpResponseRedirect('/login')
        
        username = session['username']
        error = None
        success = None
        
        if request.method == 'POST':
            # Get form data directly from request.POST
            name = request.POST.get('name', '').strip()
            description = request.POST.get('description', '').strip()
            password = request.POST.get('password', '')
            confirm_password = request.POST.get('confirm_password', '')
            emoji_picture = request.POST.get('emoji_picture', '').strip()
            is_public = request.POST.get('is_public') == 'on'  # Checkboxes return 'on' when checked
            
            # Validation
            if not name:
                error = "Group name is required"
            elif not emoji_picture:
                error = "Group emoji is required"
            elif len(emoji_picture) > 1:
                error = "The emoji picture should contain maximum 1 emoji."
            elif not password:
                error = "Password is required"
            elif password != confirm_password:
                error = "Passwords do not match"
            elif len(emoji_picture) > 10:
                error = "Emoji picture must be 10 characters or less"
            else:
                success, message = create_group(name, description, password, emoji_picture, username, is_public)
                if success:
                    return HttpResponseRedirect('/groups')
                else:
                    error = message
        
        # Load template from file
        template_path = "templates/groups/create_group.html"
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        template = Template(template_content)
        
        context = Context({
            'username': username,
            'error': error,
            'success': success
        })
        
        return HttpResponse(template.render(context))
    
    except Exception as e:
        print(f"ERROR in create_group_view: {str(e)}")
        import traceback
        print(f"TRACEBACK: {traceback.format_exc()}")
        return HttpResponse(f"Internal Server Error: {str(e)}", status=500)
    
    except Exception as e:
        print(f"ERROR in create_group_view: {str(e)}")
        import traceback
        print(f"TRACEBACK: {traceback.format_exc()}")
        return HttpResponse(f"Internal Server Error: {str(e)}", status=500)

def group_chat_view(request, group_id):
    """View for group chat"""
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    group = get_group(group_id)
    
    if not group:
        return HttpResponse('Group not found', status=404)
    
    # Check if user is member of the group
    if not is_group_member(group_id, username):
        return HttpResponseRedirect(f'/groups/join/{group_id}')
    
    # Handle group messages
    if request.method == 'POST':
        form = GroupMessageForm(request.POST, request.FILES)
        if form.is_valid():
            message = form.cleaned_data.get('message', '').strip()
            uploaded_file = form.cleaned_data.get('file')
            
            filename = None
            file_url = None
            
            if uploaded_file:
                filename, file_url = save_uploaded_file(uploaded_file)
            
            if message or filename:
                save_group_message(group_id, username, message, filename, file_url)
            
            return HttpResponseRedirect(f'/groups/{group_id}')
    else:
        form = GroupMessageForm()
    
    messages = read_group_messages(group_id)
    members = get_group_members(group_id)
    
    # Add profile picture URLs to messages
    for msg in messages:
        msg['profile_pic_url'] = get_profile_picture_url(msg['username'])
    
    # Load template from file
    template_path = "templates/groups/group_chat.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({
        'username': username,
        'group': group,
        'messages': messages,
        'members': members,
        'form': form
    })
    
    return HttpResponse(template.render(context))

def join_group_view(request, group_id):
    """View for joining a group"""
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    group = get_group(group_id)
    
    if not group:
        return HttpResponse('Group not found', status=404)
    
    # Check if user is already a member
    if is_group_member(group_id, username):
        return HttpResponseRedirect(f'/groups/{group_id}')
    
    error = None
    success = None
    
    if request.method == 'POST':
        form = JoinGroupForm(request.POST)
        if form.is_valid():
            password = form.cleaned_data['password']
            success, message = join_group(group_id, username, password)
            if success:
                return HttpResponseRedirect(f'/groups/{group_id}')
            else:
                error = message
    else:
        form = JoinGroupForm()
    
    # Load template from file
    template_path = "templates/groups/join_group.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({
        'username': username,
        'group': group,
        'form': form,
        'error': error,
        'success': success
    })
    
    return HttpResponse(template.render(context))

def bsm_profile_view(request):
    """View for displaying user's BSM profile and number"""
    # Check if BSM is enabled
    if not check_bsm_agreement():
        return HttpResponse('BSM functionality is disabled. Administrator must accept BSM A2A agreement first by creating bsm.a2a file with content "1".', status=403)
    
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    beam_number = get_user_beam_number(username)
    
    # Remove protocol from server URL for display
    server_url = get_current_server_url(request)
    server_without_protocol = server_url.replace('http://', '').replace('https://', '')
    full_beam_number = f"+{server_without_protocol} {beam_number}" if beam_number else None
    
    profile_pic_url = get_profile_picture_url(username)
    
    # Get message statistics
    user_messages = get_user_bsm_messages(username)
    sent_count = len([msg for msg in user_messages if msg['sender'] == username])
    received_count = len([msg for msg in user_messages if msg['sender'] != username])
    
    # Load template from file
    template_path = "templates/bsm/bsm_profile.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({
        'username': username,
        'beam_number': beam_number,
        'full_beam_number': full_beam_number,
        'profile_pic_url': profile_pic_url,
        'user_messages': user_messages,
        'sent_count': sent_count,
        'received_count': received_count
    })
    
    return HttpResponse(template.render(context))
def bsm_send_view(request):
    """View for sending BSM messages with protocol options"""
    # Check if BSM is enabled
    if not check_bsm_agreement():
        return HttpResponse('BSM functionality is disabled. Administrator must accept BSM A2A agreement first by creating bsm.a2a file with content "1".', status=403)
    
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    error = None
    success = None
    message_id = None
    
    if request.method == 'POST':
        # Only process messages that were sent via frontend JavaScript
        # Traditional form submission is no longer used
        error = "All BSM messages must be sent using the client-side JavaScript button"
    
    # Load template from file
    template_path = "templates/bsm/bsm_send.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({
        'username': username,
        'error': error,
        'success': success,
        'message_id': message_id
    })
    
    return HttpResponse(template.render(context))
def bsm_inbox_view(request):
    """View for displaying BSM messages"""
    # Check if BSM is enabled
    if not check_bsm_agreement():
        return HttpResponse('BSM functionality is disabled. Administrator must accept BSM A2A agreement first by creating bsm.a2a file with content "1".', status=403)
    
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    messages = get_user_bsm_messages(username)
    
    # Pre-process messages for template
    processed_messages = []
    for msg in messages:
        # Extract validation status class
        validation_status = msg.get('validation_status', 'pending')
        if ':' in validation_status:
            validation_class = validation_status.split(':')[0]
        else:
            validation_class = validation_status
        
        # Determine message direction and format display
        is_sent = msg['sender'] == username
        if is_sent:
            direction = 'sent'
            display_recipient = msg.get('recipient_beam_number', 'Unknown recipient')
        else:
            direction = 'received' 
            display_sender = f"{msg['sender']} ({msg.get('sender_server', 'Unknown server')})"
        
        processed_msg = msg.copy()
        processed_msg['validation_class'] = validation_class
        processed_msg['direction'] = direction
        processed_msg['is_sent'] = is_sent
        if is_sent:
            processed_msg['display_recipient'] = display_recipient
        else:
            processed_msg['display_sender'] = display_sender
        
        processed_messages.append(processed_msg)
    
    # Load template from file
    template_path = "templates/bsm/bsm_inbox.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({
        'username': username,
        'messages': processed_messages
    })
    
    return HttpResponse(template.render(context))

def bsm_discovery_view(request):
    """View for discovering users and their beam numbers on the same server"""
    # Check if BSM is enabled
    if not check_bsm_agreement():
        return HttpResponse('BSM functionality is disabled. Administrator must accept BSM A2A agreement first by creating bsm.a2a file with content "1".', status=403)
    
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    
    # Get all users with their beam numbers
    users = read_users()
    user_list = []
    
    for user, user_data in users.items():
        if user != username:  # Exclude current user
            beam_number = user_data.get('beam_number')
            if beam_number:
                # Remove protocol from server URL for display
                server_url = get_current_server_url(request)
                server_without_protocol = server_url.replace('http://', '').replace('https://', '')
                full_beam_number = f"+{server_without_protocol} {beam_number}"
                user_list.append({
                    'username': user,
                    'beam_number': beam_number,
                    'full_beam_number': full_beam_number,
                    'profile_pic_url': get_profile_picture_url(user),
                    'last_login': user_data.get('last_login', 'Never'),
                    'created_at': user_data.get('created_at', 'Unknown')
                })
    
    # Sort users by username
    user_list.sort(key=lambda x: x['username'].lower())
    
    # Get current server without protocol for display
    current_server = get_current_server_url(request).replace('http://', '').replace('https://', '')
    
    # Load template from file
    template_path = "templates/bsm/bsm_discovery.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({
        'username': username,
        'users': user_list,
        'current_server': current_server
    })
    
    return HttpResponse(template.render(context))
def login_view(request):
    session = get_session(request)
    if session and 'username' in session:
        return HttpResponseRedirect('/')
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            
            success, message = authenticate_user(username, password)
            if success:
                response = HttpResponseRedirect('/')
                return create_session(response, username)
            else:
                form.add_error(None, message)
    else:
        form = LoginForm()
    
        # Load template from file
    template_path = "templates/login.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({'form': form})
    return HttpResponse(template.render(context))

def register_view(request):
    session = get_session(request)
    if session and 'username' in session:
        return HttpResponseRedirect('/')
    
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            confirm_password = form.cleaned_data['confirm_password']
            
            if password != confirm_password:
                form.add_error('confirm_password', 'Passwords do not match')
            else:
                success, message = create_user(username, password)
                if success:
                    response = HttpResponseRedirect('/')
                    return create_session(response, username)
                else:
                    form.add_error(None, message)
    else:
        form = RegisterForm()
    
        # Load template from file
    template_path = "templates/register.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({'form': form})
    return HttpResponse(template.render(context))

def logout_view(request):
    response = HttpResponseRedirect('/login')
    return logout_user(response)

def settings_view(request):
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    user = get_user(username)
    profile_pic_url = get_profile_picture_url(username)
    
    # Handle profile picture upload
    if request.method == 'POST':
        if 'profile_picture' in request.FILES:
            form = ProfilePictureForm(request.POST, request.FILES)
            if form.is_valid():
                uploaded_file = form.cleaned_data.get('profile_picture')
                
                if uploaded_file:
                    # Save the new profile picture
                    filename = save_profile_picture(uploaded_file, username)
                    profile_pic_url = f"/profile_pic/{filename}"
                    
                    return HttpResponseRedirect('/settings')
    
    # Get current theme from localStorage or use default
    current_theme = {
        'primary': '#7289da',
        'secondary': '#2c2f33', 
        'background': '#23272a',
        'text': '#ffffff',
        'border': '#40444b'
    }
    
        # Load template from file
    template_path = "templates/logout.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({
        'username': username,
        'profile_pic_url': profile_pic_url
    })
    
    return HttpResponse(template.render(context))

def user_profile_view(request, username):
    """View for displaying other users' profiles"""
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    # Get the requested user's information
    user = get_user(username)
    if not user:
        return HttpResponse('User not found', status=404)
    
    profile_pic_url = get_profile_picture_url(username)
    
    # Format the registration date
    try:
        reg_date = datetime.fromisoformat(user.get('created_at', ''))
        reg_date_str = reg_date.strftime('%B %d, %Y')
    except:
        reg_date_str = 'Unknown'
    
    template_path = "templates/profile.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({
        'username': username,
        'profile_pic_url': profile_pic_url,
        'reg_date_str': reg_date_str
    })
    
    return HttpResponse(template.render(context))

def home_view(request):
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    
    if is_user_banned(username) and not is_user_admin(username):
        # Log out banned user
        response = HttpResponseRedirect('/login')
        return logout_user(response)
    
    profile_pic_url = get_profile_picture_url(username)
    
    if request.method == 'POST':
        form = ChatMessageForm(request.POST, request.FILES)
        if form.is_valid():
            message = form.cleaned_data.get('message', '').strip()
            uploaded_file = form.cleaned_data.get('file')
            
            filename = None
            file_url = None
            
            if uploaded_file:
                filename, file_url = save_uploaded_file(uploaded_file)
            
            if message or filename:
                save_chat_message(username, message, filename, file_url)
            
            return HttpResponseRedirect('/')
    else:
        form = ChatMessageForm()
    
    messages = read_chat_messages()
    bulletin_content = read_bulletin()
    
    # Filter messages for current user (show private messages only to sender and recipient)
    filtered_messages = []
    for msg in messages:
        # If message is private, only show to sender and target user
        if msg.get('is_private'):
            if msg['username'] == username or msg.get('target_user') == username:
                filtered_messages.append(msg)
        else:
            filtered_messages.append(msg)
    
        # Load template from file
    template_path = "templates/home.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    # Add profile picture URLs to messages
    for msg in filtered_messages:
        msg['profile_pic_url'] = get_profile_picture_url(msg['username'])
    
    context = Context({
        'username': username,
        'profile_pic_url': profile_pic_url,
        'messages': filtered_messages,
        'bulletin_content': bulletin_content,
        'form': form
    })
    
    return HttpResponse(template.render(context))

def admin_users_view(request):
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    
    # Updated admin check
    if not is_user_admin(username):
        return HttpResponse('Access denied', status=403)
    
    action = request.GET.get('action')
    target_user = request.GET.get('user')
    ban_reason = request.GET.get('reason', 'Violation of terms of service')
    
    # Handle ban/unban actions - prevent admins from banning themselves
    if action and target_user:
        if action == 'ban' and not is_user_admin(target_user):  # Prevent banning admins
            success = ban_user(target_user, ban_reason)
            if not success:
                return HttpResponse('User not found', status=404)
        elif action == 'unban':
            success = unban_user(target_user)
            if not success:
                return HttpResponse('User not found or not banned', status=404)
        
        return HttpResponseRedirect('/admin/users')
    
    users = get_all_users()
    banned_users = get_banned_users()
    
    # Load template from file
    template_path = "templates/admin/admin_users.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({
        'users': users,
        'banned_users': banned_users
    })
    
    return HttpResponse(template.render(context))
def admin_view(request):
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    
    # Updated admin check
    if not is_user_admin(username):
        return HttpResponse('Access denied', status=403)
    
    if request.method == 'POST':
        bulletin_content = request.POST.get('bulletin_content', '')
        write_bulletin(bulletin_content)
        return HttpResponseRedirect('/admin')
    
    bulletin_content = read_bulletin()
    
    # Load template from file
    template_path = "templates/admin/admin.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template_content = f.read()
    template = Template(template_content)
    
    context = Context({
        'username': username,
        'bulletin_content': bulletin_content
    })
    
    return HttpResponse(template.render(context))

def download_file(request, filename):
    filepath = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
    else:
        return HttpResponse('File not found', status=404)

def profile_pic_view(request, filename):
    filepath = os.path.join(PROFILE_PICS_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, 'rb') as f:
            # Determine content type based on file extension
            ext = os.path.splitext(filename)[1].lower()
            content_type = 'image/png'  # default
            if ext in ['.jpg', '.jpeg']:
                content_type = 'image/jpeg'
            elif ext == '.gif':
                content_type = 'image/gif'
            
            response = HttpResponse(f.read(), content_type=content_type)
            response['Cache-Control'] = 'max-age=3600'  # Cache for 1 hour
            return response
    else:
        return HttpResponse('Profile picture not found', status=404)


urlpatterns = [
    path('', home_view, name='home'),
    path('login', login_view, name='login'),
    path('register', register_view, name='register'),
    path('logout', logout_view, name='logout'),
    path('settings', settings_view, name='profile'),
    path('user/<str:username>', user_profile_view, name='user_profile'),
    path('admin', admin_view, name='admin'),
    path('admin/users', admin_users_view, name='admin_users'),  
    path('download/<str:filename>', download_file, name='download'),
    path('profile_pic/<str:filename>', profile_pic_view, name='profile_pic'),
    path('bsm/send', bsm_send_view, name='bsm_send'),
    path('bsm/inbox', bsm_inbox_view, name='bsm_inbox'),
    path('bsm/receive', bsm_receive_message, name='bsm_receive'),
    path('bsm/validate/<str:message_id>', bsm_validate_message, name='bsm_validate'),
    path('bsm/profile', bsm_profile_view, name='bsm_profile'),
    path('bsm/discovery', bsm_discovery_view, name='bsm_discovery'),
    path('groups', groups_list_view, name='groups_list'),
    path('groups/create', create_group_view, name='create_group'),
    path('groups/<int:group_id>', group_chat_view, name='group_chat'),
    path('groups/join/<int:group_id>', join_group_view, name='join_group'),
    path('bsm/dashboard', bsm_dashboard_view, name='bsm_dashboard'),
]

# Application
application = get_wsgi_application()

if __name__ == '__main__':
    import sys
    import argparse
    create_bsm_agreement_file()
    check_bsm_agreement()
    init_database()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='BEAM Chat Server')
    parser.add_argument('--https', action='store_true', help='Run with HTTPS')
    parser.add_argument('--port', type=int, default=8443, help='Port to run on (default: 8443 for HTTPS, 8000 for HTTP)')
    parser.add_argument('--host', default='localhost', help='Host to bind to (default: localhost)')
    parser.add_argument('--certfile', help='SSL certificate file')
    parser.add_argument('--keyfile', help='SSL private key file')

    
    args = parser.parse_args()
    
    if args.https:
        # Run with HTTPS
        run_https_server(
            host=args.host,
            port=args.port,
            certfile=args.certfile,
            keyfile=args.keyfile
        )
    else:
        # Run with HTTP (development)
        run_http_server(host=args.host, port=args.port or 8000)