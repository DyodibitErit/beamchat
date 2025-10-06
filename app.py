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

# Configure Django settings
settings.configure(
    DEBUG=True,
    SECRET_KEY='changeinprod123',
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
CHAT_FILE = 'chat_messages.txt'
BULLETIN_FILE = 'bulletin_board.txt'
USERS_FILE = 'users.json'
UPLOAD_DIR = 'uploads'
PROFILE_PICS_DIR = 'profile_pics'
ENCRYPTION_KEY_FILE = 'encryption.key'
SESSION_COOKIE_NAME = 'beam_session'
BASE_URL = "http://localhost:8000"  # Change this to your public URL if needed
USE_LOCALTUNNEL = False  # Set to True to enable localtunnel
LOCALTUNNEL_SUBDOMAIN = None  # Set to a specific subdomain if desired

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

# Message storage files
# Ensure files and directories exist
for file in [CHAT_FILE, BULLETIN_FILE, USERS_FILE]:
    if not os.path.exists(file):
        with open(file, 'w') as f:
            if file == USERS_FILE:
                f.write('{}')
            else:
                f.write('')

# Create upload directory if it doesn't exist
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# Create profile pictures directory if it doesn't exist
if not os.path.exists(PROFILE_PICS_DIR):
    os.makedirs(PROFILE_PICS_DIR)

# Forms
class ChatMessageForm(forms.Form):
    message = forms.CharField(widget=forms.Textarea, required=False)
    file = forms.FileField(required=False)

class LoginForm(forms.Form):
    username = forms.CharField(max_length=50)
    password = forms.CharField(widget=forms.PasswordInput)

class RegisterForm(forms.Form):
    username = forms.CharField(max_length=50)
    password = forms.CharField(widget=forms.PasswordInput)
    confirm_password = forms.CharField(widget=forms.PasswordInput)

class ProfilePictureForm(forms.Form):
    profile_picture = forms.ImageField(required=False)

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
    
def ban_user(username, reason="Violation of terms of service"):
    """Ban a user from the system"""
    users = read_users()
    if username in users:
        users[username]['banned'] = True
        users[username]['ban_reason'] = reason
        users[username]['banned_at'] = datetime.now().isoformat()
        save_users(users)
        return True
    return False

def unban_user(username):
    """Unban a user"""
    users = read_users()
    if username in users and users[username].get('banned', False):
        users[username]['banned'] = False
        # Keep ban history but remove active ban
        save_users(users)
        return True
    return False

def is_user_banned(username):
    """Check if a user is banned"""
    users = read_users()
    if username in users:
        return users[username].get('banned', False)
    return False

def get_banned_users():
    """Get list of all banned users"""
    users = read_users()
    banned_users = []
    for username, user_data in users.items():
        if user_data.get('banned', False):
            banned_users.append({
                'username': username,
                'ban_reason': user_data.get('ban_reason', 'No reason provided'),
                'banned_at': user_data.get('banned_at', 'Unknown'),
                'created_at': user_data.get('created_at', 'Unknown')
            })
    return banned_users

def get_all_users():
    """Get list of all users with their status"""
    users = read_users()
    user_list = []
    for username, user_data in users.items():
        user_list.append({
            'username': username,
            'banned': user_data.get('banned', False),
            'ban_reason': user_data.get('ban_reason', ''),
            'banned_at': user_data.get('banned_at', ''),
            'created_at': user_data.get('created_at', 'Unknown'),
            'last_login': user_data.get('last_login', 'Never')
        })
    return user_list

def read_users():
    """Read users from the encrypted users file"""
    try:
        with open(USERS_FILE, 'r', encoding="UTF-8") as f:
            encrypted_data = f.read()
            if encrypted_data:
                decrypted_data = decrypt_data(encrypted_data)
                return json.loads(decrypted_data)
            return {}
    except (FileNotFoundError, Exception):
        # Try to read as plaintext for backward compatibility
        try:
            with open(USERS_FILE, 'r', encoding="UTF-8") as f:
                plain_data = f.read()
                if plain_data:
                    return json.loads(plain_data)
                return {}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

def save_users(users):
    """Save users to the encrypted users file"""
    encrypted_data = encrypt_data(json.dumps(users))
    with open(USERS_FILE, 'w', encoding="UTF-8") as f:
        f.write(encrypted_data)

def create_user(username, password):
    """Create a new user"""
    users = read_users()
    if username in users:
        return False, "Username already exists"
    
    # Generate a default profile picture
    profile_pic_filename = generate_default_profile_picture(username)
    
    users[username] = {
        'password_hash': hash_password(password),
        'created_at': datetime.now().isoformat(),
        'last_login': None,
        'profile_picture': profile_pic_filename
    }
    save_users(users)
    return True, "User created successfully"

def authenticate_user(username, password):
    """Authenticate a user"""
    users = read_users()
    if username not in users:
        return False, "User not found"
    
    # Check if user is banned
    if users[username].get('banned', False):
        ban_reason = users[username].get('ban_reason', 'Violation of terms of service')
        return False, f"Account banned: {ban_reason}"
    
    if not verify_password(users[username]['password_hash'], password):
        return False, "Invalid password"
    
    # Update last login
    users[username]['last_login'] = datetime.now().isoformat()
    save_users(users)
    
    return True, "Authentication successful"

def get_user(username):
    """Get user information"""
    users = read_users()
    return users.get(username)

def update_user_profile_picture(username, profile_picture_filename):
    """Update user's profile picture"""
    users = read_users()
    if username in users:
        users[username]['profile_picture'] = profile_picture_filename
        save_users(users)
        return True
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
    """Save an uploaded profile picture"""
    # Generate a unique filename
    file_ext = os.path.splitext(uploaded_file.name)[1].lower()
    if file_ext not in ['.jpg', '.jpeg', '.png', '.gif']:
        file_ext = '.png'  # Default to png if invalid extension
    
    filename = f"{username}_profile_{uuid.uuid4().hex[:8]}{file_ext}"
    filepath = os.path.join(PROFILE_PICS_DIR, filename)
    
    # Save the file
    with open(filepath, 'wb+') as destination:
        for chunk in uploaded_file.chunks():
            destination.write(chunk)
    
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
    messages = []
    try:
        with open(CHAT_FILE, 'r', encoding="UTF-8") as f:
            for line in f:
                if line.strip():
                    try:
                        encrypted_data = json.loads(line)
                        decrypted_data = {
                            'username': decrypt_data(encrypted_data['username']),
                            'message': decrypt_data(encrypted_data['message']),
                            'timestamp': decrypt_data(encrypted_data['timestamp'])
                        }
                        if 'filename' in encrypted_data:
                            decrypted_data['filename'] = decrypt_data(encrypted_data['filename'])
                        if 'file_url' in encrypted_data:
                            decrypted_data['file_url'] = decrypt_data(encrypted_data['file_url'])
                        messages.append(decrypted_data)
                    except Exception as e:
                        print(f"Error decrypting message: {e}")
                        # Try to read as plaintext for backward compatibility
                        try:
                            plain_data = json.loads(line)
                            messages.append(plain_data)
                        except:
                            pass
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return messages

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


def save_chat_message(username, message, filename=None, file_url=None):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Check if this is an edit command
    old_word, new_word = handle_message_edit(message)
    if old_word is not None:
        # This is an edit command, find the user's last message
        messages = read_chat_messages()
        user_messages = [msg for msg in messages if msg['username'] == username]
        
        if user_messages:
            last_message = user_messages[-1]
            original_text = last_message['message']
            
            # Replace only the first occurrence
            if old_word in original_text:
                edited_text = original_text.replace(old_word, new_word, 1)
                
                # Update the message in the file
                updated_messages = []
                message_updated = False
                
                with open(CHAT_FILE, 'r', encoding="UTF-8") as f:
                    for line in f:
                        if line.strip():
                            try:
                                encrypted_data = json.loads(line)
                                decrypted_username = decrypt_data(encrypted_data['username'])
                                
                                # Find the user's last message that matches the original text
                                if (decrypted_username == username and 
                                    not message_updated and
                                    decrypt_data(encrypted_data['message']) == original_text):
                                    
                                    # Encrypt the edited message
                                    encrypted_data['message'] = encrypt_data(edited_text)
                                    message_updated = True
                                
                                updated_messages.append(json.dumps(encrypted_data) + '\n')
                            except:
                                updated_messages.append(line)
                
                # Write the updated messages back to the file
                with open(CHAT_FILE, 'w', encoding="UTF-8") as f:
                    f.writelines(updated_messages)
                
                # Return the edited message for display
                return {
                    'username': username,
                    'message': f"{edited_text} (edited)",
                    'timestamp': timestamp,
                    'filename': filename,
                    'file_url': file_url
                }
        
        # If no message was found to edit, treat as a regular message
        message = f"(edit failed) {message}"
    
    # Encrypt all data for a regular message
    encrypted_data = {
        'username': encrypt_data(username),
        'message': encrypt_data(message),
        'timestamp': encrypt_data(timestamp)
    }
    
    if filename and file_url:
        encrypted_data['filename'] = encrypt_data(filename)
        encrypted_data['file_url'] = encrypt_data(file_url)
    
    with open(CHAT_FILE, 'a', encoding="UTF-8") as f:
        f.write(json.dumps(encrypted_data) + '\n')
    
    # Return decrypted data for immediate use
    return {
        'username': username,
        'message': message,
        'timestamp': timestamp,
        'filename': filename,
        'file_url': file_url
    }

def read_bulletin():
    try:
        with open(BULLETIN_FILE, 'r', encoding="UTF-8") as f:
            encrypted_content = f.read()
            if encrypted_content:
                return decrypt_data(encrypted_content)
            return "Bulletin board is empty."
    except (FileNotFoundError, Exception):
        try:
            # Try to read as plaintext for backward compatibility
            with open(BULLETIN_FILE, 'r', encoding="UTF-8") as f:
                return f.read()
        except FileNotFoundError:
            return "Bulletin board is empty."

def write_bulletin(content):
    encrypted_content = encrypt_data(content)
    with open(BULLETIN_FILE, 'w', encoding="UTF-8") as f:
        f.write(encrypted_content)
    return content

def save_uploaded_file(uploaded_file):
    # Генерируем уникальное имя файла для предотвращения конфликтов
    file_ext = os.path.splitext(uploaded_file.name)[1]
    filename = f"{uuid.uuid4().hex}{file_ext}"
    filepath = os.path.join(UPLOAD_DIR, filename)
    
    with open(filepath, 'wb+') as destination:
        for chunk in uploaded_file.chunks():
            destination.write(chunk)
    
    return filename, f"/download/{filename}"

# LocalTunnel functions
def start_localtunnel():
    """Start localtunnel in a separate thread"""
    def run_localtunnel():
        # Wait a moment for Django to start
        time.sleep(3)
        
        try:
            cmd = 'lt --port 8000'
            if LOCALTUNNEL_SUBDOMAIN:
                cmd = f'lt --port 8000 --subdomain {LOCALTUNNEL_SUBDOMAIN}'
            
            print("Starting localtunnel...")
            print(f"Command: {cmd}")
            
            # Use os.system to execute the command
            os.system(cmd)
                
        except Exception as e:
            print(f"Error starting localtunnel: {e}")
    
    if USE_LOCALTUNNEL:
        thread = threading.Thread(target=run_localtunnel, daemon=True)
        thread.start()

# Views
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
    
    template = Template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BEAM - Login</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
    :root {
        --primary-color: #7289da;
        --secondary-color: #2c2f33;
        --border-color: #40444b;
        --text-color: #ffffff;
        --light-text: #b9bbbe;
        --background-color: #23272a;
    }
    
    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }
    
    body { 
        font-family: Arial, sans-serif; 
        background-color: var(--background-color);
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        padding: 20px;
    }
    
    .login-container {
        background-color: var(--secondary-color);
        padding: 30px;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        width: 100%;
        max-width: 400px;
        border: 1px solid var(--border-color);
    }
    
    h1 {
        text-align: center;
        margin-bottom: 20px;
        color: var(--primary-color);
    }
    
    .error {
        color: #f04747;
        margin-bottom: 15px;
        padding: 10px;
        background-color: rgba(240, 71, 71, 0.1);
        border: 1px solid rgba(240, 71, 71, 0.3);
        border-radius: 4px;
    }
    
    form {
        margin-top: 20px;
    }
    
    input { 
        display: block; 
        margin-bottom: 15px; 
        width: 100%;
        padding: 12px;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        font-family: inherit;
        font-size: 1em;
        background-color: #40444b;
        color: var(--text-color);
    }
    
    input::placeholder {
        color: var(--light-text);
    }
    
    input:focus {
        outline: none;
        border-color: var(--primary-color);
        box-shadow: 0 0 0 2px rgba(114, 137, 218, 0.3);
    }
    
    button { 
        background-color: var(--primary-color);
        color: white;
        border: none;
        padding: 12px;
        cursor: pointer;
        font-weight: bold;
        transition: background-color 0.3s;
        width: 100%;
        border-radius: 4px;
    }
    
    button:hover {
        background-color: #5b73c4;
    }
    
    .register-link {
        text-align: center;
        margin-top: 20px;
        color: var(--light-text);
    }
    
    .register-link a {
        color: var(--primary-color);
        text-decoration: none;
    }
    
    .register-link a:hover {
        text-decoration: underline;
    }
</style>
    </head>
    <body>
        <div class="login-container">
            <h1>BEAM Login</h1>
            
            {% if form.non_field_errors %}
            <div class="error">
                {% for error in form.non_field_errors %}
                    {{ error }}
                {% endfor %}
            </div>
            {% endif %}
            
            <form method="post">
                {% csrf_token %}
                <input type="text" name="username" placeholder="Username" required value="{{ form.username.value|default:'' }}">
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            
            <div class="register-link">
                <p>Don't have an account? <a href="/register">Register here</a></p>
            </div>
        </div>
    </body>
    </html>
    ''')
    
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
    
    template = Template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BEAM - Register</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
        --primary-color: #7289da;
        --secondary-color: #2c2f33;
        --border-color: #40444b;
        --text-color: #ffffff;
        --light-text: #b9bbbe;
        --background-color: #23272a;
    }
    
    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }
    
    body { 
        font-family: Arial, sans-serif; 
        background-color: var(--background-color);
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        padding: 20px;
    }
    
    .register-container {
        background-color: var(--secondary-color);
        padding: 30px;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        width: 100%;
        max-width: 400px;
        border: 1px solid var(--border-color);
    }
    
    h1 {
        text-align: center;
        margin-bottom: 20px;
        color: var(--primary-color);
    }
    
    .error {
        color: #f04747;
        margin-bottom: 15px;
        padding: 10px;
        background-color: rgba(240, 71, 71, 0.1);
        border: 1px solid rgba(240, 71, 71, 0.3);
        border-radius: 4px;
    }
    
    .field-error {
        color: #f04747;
        font-size: 0.9em;
        margin-top: -10px;
        margin-bottom: 15px;
    }
    
    form {
        margin-top: 20px;
    }
    
    input { 
        display: block; 
        margin-bottom: 5px; 
        width: 100%;
        padding: 12px;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        font-family: inherit;
        font-size: 1em;
        background-color: #40444b;
        color: var(--text-color);
    }
    
    input::placeholder {
        color: var(--light-text);
    }
    
    input:focus {
        outline: none;
        border-color: var(--primary-color);
        box-shadow: 0 0 0 2px rgba(114, 137, 218, 0.3);
    }
    
    button { 
        background-color: var(--primary-color);
        color: white;
        border: none;
        padding: 12px;
        cursor: pointer;
        font-weight: bold;
        transition: background-color 0.3s;
        width: 100%;
        border-radius: 4px;
    }
    
    button:hover {
        background-color: #5b73c4;
    }
    
    .login-link {
        text-align: center;
        margin-top: 20px;
        color: var(--light-text);
    }
    
    .login-link a {
        color: var(--primary-color);
        text-decoration: none;
    }
    
    .login-link a:hover {
        text-decoration: underline;
    }
</style>
    </head>
    <body>
        <div class="register-container">
            <h1>BEAM Register</h1>
            
            {% if form.non_field_errors %}
            <div class="error">
                {% for error in form.non_field_errors %}
                    {{ error }}
                {% endfor %}
            </div>
            {% endif %}
            
            <form method="post">
                {% csrf_token %}
                <input type="text" name="username" placeholder="Username" required value="{{ form.username.value|default:'' }}">
                {% if form.username.errors %}
                    <div class="field-error">{{ form.username.errors.0 }}</div>
                {% endif %}
                
                <input type="password" name="password" placeholder="Password" required>
                {% if form.password.errors %}
                    <div class="field-error">{{ form.password.errors.0 }}</div>
                {% endif %}
                
                <input type="password" name="confirm_password" placeholder="Confirm Password" required>
                {% if form.confirm_password.errors %}
                    <div class="field-error">{{ form.confirm_password.errors.0 }}</div>
                {% endif %}
                
                <button type="submit">Register</button>
            </form>
            
            <div class="login-link">
                <p>Already have an account? <a href="/login">Login here</a></p>
            </div>
        </div>
    </body>
    </html>
    ''')
    
    context = Context({'form': form})
    return HttpResponse(template.render(context))

def logout_view(request):
    response = HttpResponseRedirect('/login')
    return logout_user(response)

def profile_view(request):
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    user = get_user(username)
    profile_pic_url = get_profile_picture_url(username)
    
    if request.method == 'POST':
        form = ProfilePictureForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.cleaned_data.get('profile_picture')
            
            if uploaded_file:
                # Save the new profile picture
                filename = save_profile_picture(uploaded_file, username)
                profile_pic_url = f"/profile_pic/{filename}"
                
                return HttpResponseRedirect('/profile')
    else:
        form = ProfilePictureForm()
    
    template = Template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BEAM - Profile</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
    :root {
        --primary-color: #7289da;
        --secondary-color: #2c2f33;
        --border-color: #40444b;
        --text-color: #ffffff;
        --light-text: #b9bbbe;
        --background-color: #23272a;
    }
    
    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }
    
    body { 
        font-family: Arial, sans-serif; 
        background-color: var(--background-color);
        padding: 20px;
    }
    
    .container {
        max-width: 600px;
        margin: 0 auto;
        background-color: var(--secondary-color);
        padding: 30px;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        border: 1px solid var(--border-color);
    }
    
    .user-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
        padding-bottom: 10px;
        border-bottom: 1px solid var(--border-color);
    }
    
    .user-info {
        display: flex;
        align-items: center;
    }
    
    .welcome {
        margin-right: 15px;
        font-weight: bold;
        color: var(--text-color);
    }
    
    .back-btn, .logout-btn {
        background-color: var(--primary-color);
        color: white;
        border: none;
        padding: 8px 15px;
        border-radius: 4px;
        cursor: pointer;
        text-decoration: none;
        font-size: 0.9em;
        margin-left: 10px;
    }
    
    .logout-btn {
        background-color: #f04747;
    }
    
    .back-btn:hover {
        background-color: #5b73c4;
    }
    
    .logout-btn:hover {
        background-color: #d84040;
    }
    
    h1 {
        text-align: center;
        margin-bottom: 20px;
        color: var(--primary-color);
    }
    
    .profile-section {
        display: flex;
        flex-direction: column;
        align-items: center;
        margin-bottom: 30px;
    }
    
    .profile-picture {
        width: 150px;
        height: 150px;
        border-radius: 50%;
        object-fit: cover;
        margin-bottom: 20px;
        border: 3px solid var(--primary-color);
    }
    
    .profile-form {
        width: 100%;
        max-width: 400px;
    }
    
    input, button { 
        display: block; 
        margin-bottom: 15px; 
        width: 100%;
        padding: 12px;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        font-family: inherit;
        font-size: 1em;
        background-color: #40444b;
        color: var(--text-color);
    }
    
    input:focus {
        outline: none;
        border-color: var(--primary-color);
        box-shadow: 0 0 0 2px rgba(114, 137, 218, 0.3);
    }
    
    button { 
        background-color: var(--primary-color);
        color: white;
        border: none;
        padding: 12px;
        cursor: pointer;
        font-weight: bold;
        transition: background-color 0.3s;
    }
    
    button:hover {
        background-color: #5b73c4;
    }
    
    .btn-group {
        display: flex;
        gap: 10px;
    }
    
    @media (max-width: 600px) {
        .container {
            padding: 20px;
        }
        
        .user-header {
            flex-direction: column;
            align-items: flex-start;
        }
        
        .user-info {
            margin-bottom: 10px;
        }
        
        .btn-group {
            flex-direction: column;
            width: 100%;
        }
        
        .back-btn, .logout-btn {
            margin-left: 0;
            margin-bottom: 10px;
            text-align: center;
        }
    }
</style>
    </head>
    <body>
        <div class="container">
            <div class="user-header">
                <div class="user-info">
                    <span class="welcome">Profile: {{ username }}</span>
                </div>
                <div class="btn-group">
                    <a href="/" class="back-btn">Back to Chat</a>
                    <a href="/logout" class="logout-btn">Logout</a>
                </div>
            </div>
            
            <h1>Profile Settings</h1>
            
            <div class="profile-section">
                <img src="{{ profile_pic_url }}" alt="Profile Picture" class="profile-picture">
                
                <form method="post" enctype="multipart/form-data" class="profile-form">
                    {% csrf_token %}
                    <input type="file" name="profile_picture" accept="image/*">
                    <button type="submit">Update Profile Picture</button>
                </form>
            </div>
        </div>
    </body>
    </html>
    ''')
    
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
    
    template = Template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BEAM - {{ username }}'s Profile</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
    :root {
        --primary-color: #7289da;
        --secondary-color: #2c2f33;
        --border-color: #40444b;
        --text-color: #ffffff;
        --light-text: #b9bbbe;
        --background-color: #23272a;
    }
    
    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }
    
    body { 
        font-family: Arial, sans-serif; 
        background-color: var(--background-color);
        padding: 20px;
    }
    
    .container {
        max-width: 600px;
        margin: 0 auto;
        background-color: var(--secondary-color);
        padding: 30px;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        border: 1px solid var(--border-color);
    }
    
    .user-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
        padding-bottom: 10px;
        border-bottom: 1px solid var(--border-color);
    }
    
    .back-btn {
        background-color: var(--primary-color);
        color: white;
        border: none;
        padding: 8px 15px;
        border-radius: 4px;
        cursor: pointer;
        text-decoration: none;
        font-size: 0.9em;
    }
    
    .back-btn:hover {
        background-color: #5b73c4;
    }
    
    h1 {
        text-align: center;
        margin-bottom: 20px;
        color: var(--primary-color);
    }
    
    .profile-section {
        display: flex;
        flex-direction: column;
        align-items: center;
        margin-bottom: 30px;
    }
    
    .profile-picture {
        width: 150px;
        height: 150px;
        border-radius: 50%;
        object-fit: cover;
        margin-bottom: 20px;
        border: 3px solid var(--primary-color);
    }
    
    .user-info {
        text-align: center;
        color: var(--text-color);
    }
    
    .username {
        font-size: 1.5em;
        font-weight: bold;
        margin-bottom: 10px;
    }
    
    .reg-date {
        color: var(--light-text);
        font-size: 0.9em;
    }
    
    @media (max-width: 600px) {
        .container {
            padding: 20px;
        }
    }
</style>
    </head>
    <body>
        <div class="container">
            <div class="user-header">
                <a href="/" class="back-btn">Back to Chat</a>
            </div>
            
            <div class="profile-section">
                <img src="{{ profile_pic_url }}" alt="Profile Picture" class="profile-picture">
                
                <div class="user-info">
                    <div class="username">{{ username }}</div>
                    <div class="reg-date">Member since {{ reg_date_str }}</div>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''')
    
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
    
    # Check if user is banned
    if is_user_banned(username):
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
    
    template = Template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BEAM Chat</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
    :root {
        --primary-color: #7289da;
        --secondary-color: #2c2f33;
        --border-color: #40444b;
        --text-color: #ffffff;
        --light-text: #b9bbbe;
        --background-color: #23272a;
    }
    
    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }
    
    body { 
        font-family: Arial, sans-serif; 
        background-color: var(--background-color);
        padding: 20px;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
        display: flex;
        flex-direction: column;
        gap: 20px;
    }
    
    .user-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        background-color: var(--secondary-color);
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        border: 1px solid var(--border-color);
    }
    
    .user-info {
        display: flex;
        align-items: center;
    }
    
    .profile-pic {
        width: 40px;
        height: 40px;
        border-radius: 50%;
        margin-right: 15px;
        object-fit: cover;
    }
    
    .welcome {
        font-weight: bold;
        color: var(--text-color);
    }
    
    .btn-group {
        display: flex;
        gap: 10px;
    }
    
    .btn {
        background-color: var(--primary-color);
        color: white;
        border: none;
        padding: 8px 15px;
        border-radius: 4px;
        cursor: pointer;
        text-decoration: none;
        font-size: 0.9em;
    }
    
    .btn:hover {
        background-color: #5b73c4;
    }
    
    .btn-profile {
        background-color: #43b581;
    }
    
    .btn-profile:hover {
        background-color: #3ca374;
    }
    
    .btn-logout {
        background-color: #f04747;
    }
    
    .btn-logout:hover {
        background-color: #d84040;
    }
    
    .main-content {
        display: flex;
        gap: 20px;
    }
    
    .chat-section {
        flex: 3;
        background-color: var(--secondary-color);
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        border: 1px solid var(--border-color);
        display: flex;
        flex-direction: column;
        height: 70vh;
    }
    
    .bulletin-section {
        flex: 1;
        background-color: var(--secondary-color);
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        border: 1px solid var(--border-color);
        padding: 20px;
        max-height: 70vh;
        overflow-y: auto;
    }
    
    .chat-header {
        padding: 15px 20px;
        border-bottom: 1px solid var(--border-color);
        color: var(--primary-color);
        font-weight: bold;
    }
    
    .messages {
        flex: 1;
        overflow-y: auto;
        padding: 20px;
        display: flex;
        flex-direction: column;
        gap: 15px;
    }
    
    .message {
        display: flex;
        gap: 10px;
        padding: 10px;
        border-radius: 8px;
        background-color: rgba(255, 255, 255, 0.05);
    }
    
    .message:hover {
        background-color: rgba(255, 255, 255, 0.08);
    }
    
    .message-user-pic {
        width: 40px;
        height: 40px;
        border-radius: 50%;
        object-fit: cover;
    }
    
    .message-content {
        flex: 1;
    }
    
    .message-header {
        display: flex;
        align-items: center;
        margin-bottom: 5px;
    }
    
    .message-username {
        font-weight: bold;
        color: var(--primary-color);
        text-decoration: none;
    }
    
    .message-username:hover {
        text-decoration: underline;
    }
    
    .message-time {
        color: var(--light-text);
        font-size: 0.8em;
        margin-left: 10px;
    }
    
    .message-text {
        color: var(--text-color);
        word-break: break-word;
    }
    
    .message-file {
        margin-top: 10px;
    }
    
    .file-link {
        color: var(--primary-color);
        text-decoration: none;
        display: inline-flex;
        align-items: center;
        gap: 5px;
    }
    
    .file-link:hover {
        text-decoration: underline;
    }
    
    .chat-form {
        padding: 20px;
        border-top: 1px solid var(--border-color);
    }
    
    textarea {
        width: 100%;
        height: 80px;
        padding: 12px;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        font-family: inherit;
        font-size: 1em;
        background-color: #40444b;
        color: var(--text-color);
        resize: vertical;
        margin-bottom: 10px;
    }
    
    textarea:focus {
        outline: none;
        border-color: var(--primary-color);
        box-shadow: 0 0 0 2px rgba(114, 137, 218, 0.3);
    }
    
    .form-actions {
        display: flex;
        gap: 10px;
    }
    
    .file-input {
        flex: 1;
        padding: 10px;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        background-color: #40444b;
        color: var(--text-color);
    }
    
    .submit-btn {
        background-color: var(--primary-color);
        color: white;
        border: none;
        padding: 10px 20px;
        border-radius: 4px;
        cursor: pointer;
        font-weight: bold;
    }
    
    .submit-btn:hover {
        background-color: #5b73c4;
    }
    
    .bulletin-header {
        color: var(--primary-color);
        font-weight: bold;
        margin-bottom: 15px;
        padding-bottom: 10px;
        border-bottom: 1px solid var(--border-color);
    }
    
    .bulletin-content {
        color: var(--text-color);
        white-space: pre-wrap;
        line-height: 1.5;
    }
    
    @media (max-width: 768px) {
        .main-content {
            flex-direction: column;
        }
        
        .chat-section, .bulletin-section {
            flex: none;
        }
        
        .bulletin-section {
            max-height: 300px;
        }
    }
</style>
    </head>
    <body>
        <div class="container">
            <div class="user-header">
                <div class="user-info">
                    <img src="{{ profile_pic_url }}" alt="Profile Picture" class="profile-pic">
                    <span class="welcome">Welcome, {{ username }}!</span>
                </div>
                <div class="btn-group">
                    <a href="/profile" class="btn btn-profile">My Profile</a>
                    <a href="/logout" class="btn btn-logout">Logout</a>
                </div>
            </div>
            
            <div class="main-content">
                <div class="chat-section">
                    <div class="chat-header">Chat</div>
                    <div class="messages" id="messages">
                        {% for msg in messages %}
                        <div class="message">
                            <a href="/user/{{ msg.username }}">
                                <img src="{{ msg.profile_pic_url }}" alt="{{ msg.username }}" class="message-user-pic">
                            </a>
                            <div class="message-content">
                                <div class="message-header">
                                    <a href="/user/{{ msg.username }}" class="message-username">{{ msg.username }}</a>
                                    <span class="message-time">{{ msg.timestamp }}</span>
                                </div>
                                <div class="message-text">{{ msg.message }}</div>
                                {% if msg.filename and msg.file_url %}
                                <div class="message-file">
                                    <a href="{{ msg.file_url }}" class="file-link" target="_blank">
                                        📎 {{ msg.filename }}
                                    </a>
                                </div>
                                {% endif %}
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                    <form method="post" enctype="multipart/form-data" class="chat-form">
                        {% csrf_token %}
                        <textarea name="message" placeholder="Type your message here... (Use s/old/new to edit your last message)"></textarea>
                        <div class="form-actions">
                            <input type="file" name="file" class="file-input">
                            <button type="submit" class="submit-btn">Send</button>
                        </div>
                    </form>
                </div>
                
                <div class="bulletin-section">
                    <div class="bulletin-header">Bulletin Board</div>
                    <div class="bulletin-content">{{ bulletin_content }}</div>
                </div>
            </div>
        </div>
        
        <script>
            // Auto-scroll to bottom of messages
            const messagesContainer = document.getElementById('messages');
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
            
            // Refresh page every 30 seconds to get new messages
            setTimeout(() => {
                window.location.reload();
            }, 30000);
        </script>
    </body>
    </html>
    ''')
    
    # Add profile picture URLs to messages
    for msg in messages:
        msg['profile_pic_url'] = get_profile_picture_url(msg['username'])
    
    context = Context({
        'username': username,
        'profile_pic_url': profile_pic_url,
        'messages': messages,
        'bulletin_content': bulletin_content,
        'form': form
    })
    
    return HttpResponse(template.render(context))

def admin_users_view(request):
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    
    # Simple admin check
    if username != 'admin':
        return HttpResponse('Access denied', status=403)
    
    action = request.GET.get('action')
    target_user = request.GET.get('user')
    ban_reason = request.GET.get('reason', 'Violation of terms of service')
    
    # Handle ban/unban actions
    if action and target_user:
        if action == 'ban' and target_user != 'admin':  # Prevent banning admin
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
    
    template = Template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BEAM - User Management</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
    :root {
        --primary-color: #7289da;
        --secondary-color: #2c2f33;
        --border-color: #40444b;
        --text-color: #ffffff;
        --light-text: #b9bbbe;
        --background-color: #23272a;
        --danger-color: #f04747;
        --success-color: #43b581;
    }
    
    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }
    
    body { 
        font-family: Arial, sans-serif; 
        background-color: var(--background-color);
        padding: 20px;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
        background-color: var(--secondary-color);
        padding: 30px;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        border: 1px solid var(--border-color);
    }
    
    .admin-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 30px;
        padding-bottom: 15px;
        border-bottom: 1px solid var(--border-color);
    }
    
    .admin-nav {
        display: flex;
        gap: 10px;
        margin-bottom: 20px;
    }
    
    .nav-btn {
        background-color: var(--primary-color);
        color: white;
        border: none;
        padding: 8px 15px;
        border-radius: 4px;
        cursor: pointer;
        text-decoration: none;
        font-size: 0.9em;
    }
    
    .nav-btn:hover {
        background-color: #5b73c4;
    }
    
    .nav-btn.active {
        background-color: #43b581;
    }
    
    h1 {
        color: var(--primary-color);
        margin-bottom: 20px;
    }
    
    h2 {
        color: var(--text-color);
        margin: 30px 0 15px 0;
        padding-bottom: 10px;
        border-bottom: 1px solid var(--border-color);
    }
    
    .user-table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 30px;
    }
    
    .user-table th,
    .user-table td {
        padding: 12px;
        text-align: left;
        border-bottom: 1px solid var(--border-color);
        color: var(--text-color);
    }
    
    .user-table th {
        background-color: rgba(255, 255, 255, 0.05);
        color: var(--primary-color);
        font-weight: bold;
    }
    
    .user-table tr:hover {
        background-color: rgba(255, 255, 255, 0.03);
    }
    
    .banned-user {
        background-color: rgba(240, 71, 71, 0.1);
    }
    
    .ban-btn {
        background-color: var(--danger-color);
        color: white;
        border: none;
        padding: 6px 12px;
        border-radius: 4px;
        cursor: pointer;
        text-decoration: none;
        font-size: 0.8em;
    }
    
    .unban-btn {
        background-color: var(--success-color);
        color: white;
        border: none;
        padding: 6px 12px;
        border-radius: 4px;
        cursor: pointer;
        text-decoration: none;
        font-size: 0.8em;
    }
    
    .ban-btn:hover {
        background-color: #d84040;
    }
    
    .unban-btn:hover {
        background-color: #3ca374;
    }
    
    .ban-form {
        display: inline;
    }
    
    .ban-reason-input {
        padding: 4px 8px;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        background-color: #40444b;
        color: var(--text-color);
        margin-right: 5px;
        width: 200px;
    }
    
    .empty-state {
        text-align: center;
        color: var(--light-text);
        padding: 40px;
        font-style: italic;
    }
    
    .status-badge {
        display: inline-block;
        padding: 4px 8px;
        border-radius: 12px;
        font-size: 0.8em;
        font-weight: bold;
    }
    
    .status-banned {
        background-color: var(--danger-color);
        color: white;
    }
    
    .status-active {
        background-color: var(--success-color);
        color: white;
    }
</style>
    </head>
    <body>
        <div class="container">
            <div class="admin-header">
                <h1>User Management</h1>
                <a href="/" class="nav-btn">Back to Chat</a>
            </div>
            
            <div class="admin-nav">
                <a href="/admin" class="nav-btn">Bulletin Board</a>
                <a href="/admin/users" class="nav-btn active">User Management</a>
            </div>
            
            <h2>Banned Users ({{ banned_users|length }})</h2>
            {% if banned_users %}
            <table class="user-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Ban Reason</th>
                        <th>Banned At</th>
                        <th>Account Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in banned_users %}
                    <tr class="banned-user">
                        <td>{{ user.username }}</td>
                        <td>{{ user.ban_reason }}</td>
                        <td>{{ user.banned_at }}</td>
                        <td>{{ user.created_at }}</td>
                        <td>
                            <a href="/admin/users?action=unban&user={{ user.username }}" class="unban-btn">Unban</a>
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty-state">No banned users</div>
            {% endif %}
            
            <h2>All Users ({{ users|length }})</h2>
            {% if users %}
            <table class="user-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Status</th>
                        <th>Last Login</th>
                        <th>Account Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user.username }}</td>
                        <td>
                            {% if user.banned %}
                            <span class="status-badge status-banned">Banned</span>
                            {% else %}
                            <span class="status-badge status-active">Active</span>
                            {% endif %}
                        </td>
                        <td>{{ user.last_login }}</td>
                        <td>{{ user.created_at }}</td>
                        <td>
                            {% if not user.banned and user.username != 'admin' %}
                            <form class="ban-form" method="get" action="/admin/users">
                                <input type="hidden" name="action" value="ban">
                                <input type="hidden" name="user" value="{{ user.username }}">
                                <input type="text" name="reason" placeholder="Ban reason" class="ban-reason-input" value="Violation of terms of service">
                                <button type="submit" class="ban-btn">Ban</button>
                            </form>
                            {% elif user.banned %}
                            <a href="/admin/users?action=unban&user={{ user.username }}" class="unban-btn">Unban</a>
                            {% else %}
                            <em>No actions</em>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty-state">No users found</div>
            {% endif %}
        </div>
    </body>
    </html>
    ''')
    
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
    
    # Simple admin check - in a real app, you'd have proper admin roles
    if username != 'admin':
        return HttpResponse('Access denied', status=403)
    
    if request.method == 'POST':
        bulletin_content = request.POST.get('bulletin_content', '')
        write_bulletin(bulletin_content)
        return HttpResponseRedirect('/admin')
    
    bulletin_content = read_bulletin()
    
    template = Template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BEAM - Admin Panel</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
    :root {
        --primary-color: #7289da;
        --secondary-color: #2c2f33;
        --border-color: #40444b;
        --text-color: #ffffff;
        --light-text: #b9bbbe;
        --background-color: #23272a;
    }
    
    * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
    }
    
    body { 
        font-family: Arial, sans-serif; 
        background-color: var(--background-color);
        padding: 20px;
    }
    
    .container {
        max-width: 800px;
        margin: 0 auto;
        background-color: var(--secondary-color);
        padding: 30px;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
        border: 1px solid var(--border-color);
    }
    
    .user-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
        padding-bottom: 10px;
        border-bottom: 1px solid var(--border-color);
    }
    
    .admin-nav {
        display: flex;
        gap: 10px;
        margin-bottom: 20px;
    }
    
    .nav-btn {
        background-color: var(--primary-color);
        color: white;
        border: none;
        padding: 8px 15px;
        border-radius: 4px;
        cursor: pointer;
        text-decoration: none;
        font-size: 0.9em;
    }
    
    .nav-btn.active {
        background-color: #43b581;
    }
    
    .nav-btn:hover {
        background-color: #5b73c4;
    }
    
    h1 {
        text-align: center;
        margin-bottom: 20px;
        color: var(--primary-color);
    }
    
    textarea {
        width: 100%;
        height: 300px;
        padding: 15px;
        border: 1px solid var(--border-color);
        border-radius: 4px;
        font-family: inherit;
        font-size: 1em;
        background-color: #40444b;
        color: var(--text-color);
        resize: vertical;
        margin-bottom: 15px;
    }
    
    textarea:focus {
        outline: none;
        border-color: var(--primary-color);
        box-shadow: 0 0 0 2px rgba(114, 137, 218, 0.3);
    }
    
    button { 
        background-color: var(--primary-color);
        color: white;
        border: none;
        padding: 12px 20px;
        cursor: pointer;
        font-weight: bold;
        transition: background-color 0.3s;
        border-radius: 4px;
        width: 100%;
    }
    
    button:hover {
        background-color: #5b73c4;
    }
</style>
    </head>
    <body>
        <div class="container">
            <div class="user-header">
                <span>Admin Panel</span>
                <a href="/" class="nav-btn">Back to Chat</a>
            </div>
            
            <div class="admin-nav">
                <a href="/admin" class="nav-btn active">Bulletin Board</a>
                <a href="/admin/users" class="nav-btn">User Management</a>
            </div>
            
            <h1>Bulletin Board Editor</h1>
            
            <form method="post">
                {% csrf_token %}
                <textarea name="bulletin_content" placeholder="Enter bulletin board content...">{{ bulletin_content }}</textarea>
                <button type="submit">Update Bulletin Board</button>
            </form>
        </div>
    </body>
    </html>
    ''')
    
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
    path('profile', profile_view, name='profile'),
    path('user/<str:username>', user_profile_view, name='user_profile'),
    path('admin', admin_view, name='admin'),
    path('admin/users', admin_users_view, name='admin_users'),  # Add this line
    path('download/<str:filename>', download_file, name='download'),
    path('profile_pic/<str:filename>', profile_pic_view, name='profile_pic'),
]

# Application
application = get_wsgi_application()

if __name__ == '__main__':
    import sys
    from django.core.management import execute_from_command_line
    
    # Start localtunnel if enabled
    if USE_LOCALTUNNEL:
        start_localtunnel()
    
    # Run the Django development server
    execute_from_command_line([sys.argv[0], 'runserver', '0.0.0.0:8000'])