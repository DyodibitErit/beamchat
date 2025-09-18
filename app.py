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
USE_LOCALTUNNEL = True  # Set to False to disable localtunnel
LOCALTUNNEL_SUBDOMAIN = "beamchat-indev-test"  # Set to a specific subdomain if desired

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
    y = (size - text_height) / 2
    
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

def save_chat_message(username, message, filename=None, file_url=None):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Encrypt all data
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
                --primary-color: #3366cc;
                --secondary-color: #f9f9f9;
                --border-color: #ddd;
                --text-color: #333;
                --light-text: #999;
            }
            
            * {
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }
            
            body { 
                font-family: Arial, sans-serif; 
                background-color: #f5f5f5;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
            }
            
            .login-container {
                background-color: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                width: 100%;
                max-width: 400px;
            }
            
            h1 {
                text-align: center;
                margin-bottom: 20px;
                color: var(--primary-color);
            }
            
            .error {
                color: #d9534f;
                margin-bottom: 15px;
                padding: 10px;
                background-color: #f8d7da;
                border: 1px solid #f5c6cb;
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
            }
            
            input:focus {
                outline: none;
                border-color: var(--primary-color);
                box-shadow: 0 0 0 2px rgba(51, 102, 204, 0.2);
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
            }
            
            button:hover {
                background-color: #254e9e;
            }
            
            .register-link {
                text-align: center;
                margin-top: 20px;
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
                --primary-color: #3366cc;
                --secondary-color: #f9f9f9;
                --border-color: #ddd;
                --text-color: #333;
                --light-text: #999;
            }
            
            * {
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }
            
            body { 
                font-family: Arial, sans-serif; 
                background-color: #f5f5f5;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
            }
            
            .register-container {
                background-color: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                width: 100%;
                max-width: 400px;
            }
            
            h1 {
                text-align: center;
                margin-bottom: 20px;
                color: var(--primary-color);
            }
            
            .error {
                color: #d9534f;
                margin-bottom: 15px;
                padding: 10px;
                background-color: #f8d7da;
                border: 1px solid #f5c6cb;
                border-radius: 4px;
            }
            
            .field-error {
                color: #d9534f;
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
            }
            
            input:focus {
                outline: none;
                border-color: var(--primary-color);
                box-shadow: 0 0 0 2px rgba(51, 102, 204, 0.2);
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
            }
            
            button:hover {
                background-color: #254e9e;
            }
            
            .login-link {
                text-align: center;
                margin-top: 20px;
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
                --primary-color: #3366cc;
                --secondary-color: #f9f9f9;
                --border-color: #ddd;
                --text-color: #333;
                --light-text: #999;
            }
            
            * {
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }
            
            body { 
                font-family: Arial, sans-serif; 
                background-color: #f5f5f5;
                padding: 20px;
            }
            
            .container {
                max-width: 600px;
                margin: 0 auto;
                background-color: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
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
                background-color: #dc3545;
            }
            
            .back-btn:hover {
                background-color: #254e9e;
            }
            
            .logout-btn:hover {
                background-color: #c82333;
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
            }
            
            input:focus {
                outline: none;
                border-color: var(--primary-color);
                box-shadow: 0 0 0 2px rgba(51, 102, 204, 0.2);
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
                background-color: #254e9e;
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
        reg_date = datetime.fromisoformat(user['created_at']).strftime('%B %d, %Y')
    except:
        reg_date = "Unknown date"
    
    template = Template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BEAM - {{ username }}'s Profile</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root {
                --primary-color: #3366cc;
                --secondary-color: #f9f9f9;
                --border-color: #ddd;
                --text-color: #333;
                --light-text: #999;
            }
            
            * {
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }
            
            body { 
                font-family: Arial, sans-serif; 
                background-color: #f5f5f5;
                padding: 20px;
            }
            
            .container {
                max-width: 600px;
                margin: 0 auto;
                background-color: white;
                padding: 30px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
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
                background-color: #254e9e;
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
                width: 200px;
                height: 200px;
                border-radius: 50%;
                object-fit: cover;
                margin-bottom: 20px;
                border: 3px solid var(--primary-color);
            }
            
            .user-details {
                text-align: center;
                margin-bottom: 20px;
            }
            
            .username-large {
                font-size: 1.5em;
                font-weight: bold;
                margin-bottom: 10px;
                color: var(--primary-color);
            }
            
            .registration-date {
                color: var(--light-text);
                font-size: 0.9em;
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
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="user-header">
                <div class="user-info">
                    <span class="welcome">Viewing Profile</span>
                </div>
                <a href="/" class="back-btn">Back to Chat</a>
            </div>
            
            <h1>User Profile</h1>
            
            <div class="profile-section">
                <img src="{{ profile_pic_url }}" alt="{{ username }}'s Profile Picture" class="profile-picture">
                
                <div class="user-details">
                    <div class="username-large">{{ username }}</div>
                    <div class="registration-date">Member since: {{ reg_date }}</div>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''')
    
    context = Context({
        'username': username,
        'profile_pic_url': profile_pic_url,
        'reg_date': reg_date
    })
    
    return HttpResponse(template.render(context))

def index_view(request):
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    messages = read_chat_messages()
    bulletin = read_bulletin()
    
    if request.method == 'POST':
        form = ChatMessageForm(request.POST, request.FILES)
        if form.is_valid():
            message = form.cleaned_data['message']
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
    
    template = Template('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>BEAM Chat</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            :root {
                --primary-color: #3366cc;
                --secondary-color: #f9f9f9;
                --border-color: #ddd;
                --text-color: #333;
                --light-text: #999;
            }
            
            * {
                box-sizing: border-box;
                margin: 0;
                padding: 0;
            }
            
            body { 
                font-family: Arial, sans-serif; 
                background-color: #f5f5f5;
                padding: 20px;
            }
            
            .container {
                max-width: 1000px;
                margin: 0 auto;
                display: grid;
                grid-template-columns: 1fr 300px;
                gap: 20px;
            }
            
            @media (max-width: 768px) {
                .container {
                    grid-template-columns: 1fr;
                }
            }
            
            .chat-container, .bulletin-container {
                background-color: white;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
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
            }
            
            .profile-pic {
                width: 30px;
                height: 30px;
                border-radius: 50%;
                object-fit: cover;
                margin-right: 10px;
            }
            
            .profile-btn, .logout-btn {
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
                background-color: #dc3545;
            }
            
            .profile-btn:hover {
                background-color: #254e9e;
            }
            
            .logout-btn:hover {
                background-color: #c82333;
            }
            
            .chat-messages {
                max-height: 500px;
                overflow-y: auto;
                margin-bottom: 20px;
                padding: 10px;
                border: 1px solid var(--border-color);
                border-radius: 4px;
            }
            
            .message {
                margin-bottom: 15px;
                padding: 10px;
                border-radius: 4px;
                background-color: var(--secondary-color);
            }
            
            .message-header {
                display: flex;
                justify-content: space-between;
                margin-bottom: 5px;
                font-size: 0.9em;
                color: var(--light-text);
            }
            
            .username {
                font-weight: bold;
                color: var(--primary-color);
                text-decoration: none;
            }
            
            .username:hover {
                text-decoration: underline;
            }
            
            .timestamp {
                color: var(--light-text);
            }
            
            .message-content {
                margin-bottom: 5px;
                word-break: break-word;
            }
            
            .file-attachment {
                margin-top: 5px;
                padding: 5px;
                background-color: rgba(51, 102, 204, 0.1);
                border-radius: 4px;
            }
            
            .file-attachment a {
                color: var(--primary-color);
                text-decoration: none;
            }
            
            .file-attachment a:hover {
                text-decoration: underline;
            }
            
            .chat-form textarea {
                width: 100%;
                padding: 10px;
                border: 1px solid var(--border-color);
                border-radius: 4px;
                resize: vertical;
                min-height: 80px;
                margin-bottom: 10px;
                font-family: inherit;
            }
            
            .file-input {
                margin-bottom: 10px;
            }
            
            .chat-form button {
                background-color: var(--primary-color);
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                cursor: pointer;
                font-weight: bold;
                transition: background-color 0.3s;
            }
            
            .chat-form button:hover {
                background-color: #254e9e;
            }
            
            .bulletin-container h2 {
                margin-bottom: 15px;
                color: var(--primary-color);
                border-bottom: 1px solid var(--border-color);
                padding-bottom: 10px;
            }
            
            .bulletin-content {
                white-space: pre-wrap;
                word-break: break-word;
                line-height: 1.5;
            }
            
            .bulletin-form {
                margin-top: 20px;
            }
            
            .bulletin-form textarea {
                width: 100%;
                padding: 10px;
                border: 1px solid var(--border-color);
                border-radius: 4px;
                resize: vertical;
                min-height: 100px;
                margin-bottom: 10px;
                font-family: inherit;
            }
            
            .bulletin-form button {
                background-color: var(--primary-color);
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                cursor: pointer;
                font-weight: bold;
                transition: background-color 0.3s;
            }
            
            .bulletin-form button:hover {
                background-color: #254e9e;
            }
            
            .btn-group {
                display: flex;
                gap: 10px;
            }
            
            @media (max-width: 600px) {
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
                
                .profile-btn, .logout-btn {
                    margin-left: 0;
                    margin-bottom: 10px;
                    text-align: center;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="chat-container">
                <div class="user-header">
                    <div class="user-info">
                        <img src="{{ profile_pic_url }}" alt="Your Profile Picture" class="profile-pic">
                        <span class="welcome">Welcome, {{ username }}!</span>
                    </div>
                    <div class="btn-group">
                        <a href="/profile" class="profile-btn">Your Profile</a>
                        <a href="/logout" class="logout-btn">Logout</a>
                    </div>
                </div>
                
                <div class="chat-messages">
                    {% for msg in messages %}
                    <div class="message">
                        <div class="message-header">
                            <a href="/user/{{ msg.username }}" class="username">{{ msg.username }}</a>
                            <span class="timestamp">{{ msg.timestamp }}</span>
                        </div>
                        {% if msg.message %}
                        <div class="message-content">{{ msg.message }}</div>
                        {% endif %}
                        {% if msg.filename and msg.file_url %}
                        <div class="file-attachment">
                            📎 <a href="{{ msg.file_url }}" target="_blank">{{ msg.filename }}</a>
                        </div>
                        {% endif %}
                    </div>
                    {% endfor %}
                </div>
                
                <form method="post" enctype="multipart/form-data" class="chat-form">
                    {% csrf_token %}
                    <textarea name="message" placeholder="Type your message here..."></textarea>
                    <div class="file-input">
                        <input type="file" name="file">
                    </div>
                    <button type="submit">Send Message</button>
                </form>
            </div>
            
            <div class="bulletin-container">
                <h2>Bulletin Board</h2>
                <div class="bulletin-content">{{ bulletin }}</div>
                
                {% if username == 'admin' %}
                <form method="post" action="/update_bulletin" class="bulletin-form">
                    {% csrf_token %}
                    <textarea name="bulletin_content" placeholder="Update bulletin board content...">{{ bulletin }}</textarea>
                    <button type="submit">Update Bulletin</button>
                </form>
                {% endif %}
            </div>
        </div>
        
        <script>
            // Auto-scroll to the bottom of the chat messages
            window.onload = function() {
                const messagesContainer = document.querySelector('.chat-messages');
                if (messagesContainer) {
                    messagesContainer.scrollTop = messagesContainer.scrollHeight;
                }
            };
        </script>
    </body>
    </html>
    ''')
    
    profile_pic_url = get_profile_picture_url(username)
    
    context = Context({
        'username': username,
        'messages': messages,
        'bulletin': bulletin,
        'profile_pic_url': profile_pic_url
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
            content_type = 'image/jpeg'
            if ext == '.png':
                content_type = 'image/png'
            elif ext == '.gif':
                content_type = 'image/gif'
            
            response = HttpResponse(f.read(), content_type=content_type)
            response['Cache-Control'] = 'max-age=3600'  # Cache for 1 hour
            return response
    else:
        return HttpResponse('Profile picture not found', status=404)

@csrf_exempt
@require_http_methods(["POST"])
def update_bulletin_view(request):
    session = get_session(request)
    if not session or 'username' not in session or session['username'] != 'admin':
        return HttpResponse('Unauthorized', status=403)
    
    content = request.POST.get('bulletin_content', '')
    write_bulletin(content)
    return HttpResponseRedirect('/')

# API endpoints
@csrf_exempt
def api_chat_messages(request):
    if request.method == 'GET':
        messages = read_chat_messages()
        return JsonResponse(messages, safe=False)
    elif request.method == 'POST':
        session = get_session(request)
        if not session or 'username' not in session:
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        
        username = session['username']
        data = json.loads(request.body)
        message = data.get('message', '')
        
        if message:
            new_message = save_chat_message(username, message)
            return JsonResponse(new_message)
        else:
            return JsonResponse({'error': 'Message is required'}, status=400)

@csrf_exempt
def api_bulletin(request):
    if request.method == 'GET':
        bulletin = read_bulletin()
        return JsonResponse({'content': bulletin})
    elif request.method == 'POST':
        session = get_session(request)
        if not session or 'username' not in session or session['username'] != 'admin':
            return JsonResponse({'error': 'Unauthorized'}, status=401)
        
        data = json.loads(request.body)
        content = data.get('content', '')
        write_bulletin(content)
        return JsonResponse({'success': True})

# URL patterns
urlpatterns = [
    path('', index_view, name='index'),
    path('login', login_view, name='login'),
    path('register', register_view, name='register'),
    path('logout', logout_view, name='logout'),
    path('profile', profile_view, name='profile'),
    path('user/<str:username>', user_profile_view, name='user_profile'),
    path('download/<str:filename>', download_file, name='download'),
    path('profile_pic/<str:filename>', profile_pic_view, name='profile_pic'),
    path('update_bulletin', update_bulletin_view, name='update_bulletin'),
    path('api/chat', api_chat_messages, name='api_chat'),
    path('api/bulletin', api_bulletin, name='api_bulletin'),
]

# Application
application = get_wsgi_application()

# Run the server
if __name__ == '__main__':
    import sys
    from django.core.management import execute_from_command_line
    
    # Start localtunnel if enabled
    start_localtunnel()
    
    # Print server information
    print("Starting BEAM Chat Server...")
    print(f"Local URL: http://localhost:8000")
    
    if USE_LOCALTUNNEL:
        print("Localtunnel is enabled. Waiting for public URL...")
        print("(It may take a few seconds for the public URL to appear)")
    else:
        print("Localtunnel is disabled. Only accessible on local network.")
    
    # Run the Django development server
    execute_from_command_line([sys.argv[0], 'runserver', '0.0.0.0:8000'])