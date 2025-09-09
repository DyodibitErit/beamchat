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
ENCRYPTION_KEY_FILE = 'encryption.key'
SESSION_COOKIE_NAME = 'beam_session'
BASE_URL = "http://localhost:8000"  # Change this to your public URL if needed
USE_LOCALTUNNEL = True  # Set to False to disable localtunnel
LOCALTUNNEL_SUBDOMAIN = None  # Set to a specific subdomain if desired

# WebRTC signaling - simple in-memory storage (for demo purposes)
# In production, use Redis or database for signaling
webrtc_offers = {}
webrtc_answers = {}
webrtc_ice_candidates = {}

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
    
    users[username] = {
        'password_hash': hash_password(password),
        'created_at': datetime.now().isoformat(),
        'last_login': None
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

# WebRTC signaling functions
@csrf_exempt
@require_http_methods(["POST"])
def webrtc_offer(request):
    """Store WebRTC offer from a user"""
    try:
        data = json.loads(request.body)
        username = data.get('username')
        target = data.get('target')
        offer = data.get('offer')
        
        if not username or not target or not offer:
            return JsonResponse({'error': 'Missing parameters'}, status=400)
        
        # Store the offer
        if target not in webrtc_offers:
            webrtc_offers[target] = {}
        webrtc_offers[target][username] = offer
        
        return JsonResponse({'status': 'offer stored'})
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

@csrf_exempt
@require_http_methods(["GET"])
def webrtc_get_offer(request, username):
    """Get WebRTC offer for a user"""
    if username in webrtc_offers:
        return JsonResponse({'offers': webrtc_offers[username]})
    return JsonResponse({'offers': {}})

@csrf_exempt
@require_http_methods(["POST"])
def webrtc_answer(request):
    """Store WebRTC answer from a user"""
    try:
        data = json.loads(request.body)
        username = data.get('username')
        target = data.get('target')
        answer = data.get('answer')
        
        if not username or not target or not answer:
            return JsonResponse({'error': 'Missing parameters'}, status=400)
        
        # Store the answer
        if target not in webrtc_answers:
            webrtc_answers[target] = {}
        webrtc_answers[target][username] = answer
        
        return JsonResponse({'status': 'answer stored'})
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

@csrf_exempt
@require_http_methods(["GET"])
def webrtc_get_answer(request, username):
    """Get WebRTC answer for a user"""
    if username in webrtc_answers:
        return JsonResponse({'answers': webrtc_answers[username]})
    return JsonResponse({'answers': {}})

@csrf_exempt
@require_http_methods(["POST"])
def webrtc_ice_candidate(request):
    """Store ICE candidate from a user"""
    try:
        data = json.loads(request.body)
        username = data.get('username')
        target = data.get('target')
        candidate = data.get('candidate')
        
        if not username or not target or not candidate:
            return JsonResponse({'error': 'Missing parameters'}, status=400)
        
        # Store the ICE candidate
        if target not in webrtc_ice_candidates:
            webrtc_ice_candidates[target] = {}
        if username not in webrtc_ice_candidates[target]:
            webrtc_ice_candidates[target][username] = []
        
        webrtc_ice_candidates[target][username].append(candidate)
        
        return JsonResponse({'status': 'ICE candidate stored'})
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

@csrf_exempt
@require_http_methods(["GET"])
def webrtc_get_ice_candidates(request, username):
    """Get ICE candidates for a user"""
    if username in webrtc_ice_candidates:
        return JsonResponse({'candidates': webrtc_ice_candidates[username]})
    return JsonResponse({'candidates': {}})

@csrf_exempt
@require_http_methods(["POST"])
def webrtc_cleanup(request):
    """Clean up WebRTC signaling data for a user"""
    try:
        data = json.loads(request.body)
        username = data.get('username')
        
        if not username:
            return JsonResponse({'error': 'Username required'}, status=400)
        
        # Remove user from all signaling data
        for target in list(webrtc_offers.keys()):
            if username in webrtc_offers[target]:
                del webrtc_offers[target][username]
            if not webrtc_offers[target]:
                del webrtc_offers[target]
        
        for target in list(webrtc_answers.keys()):
            if username in webrtc_answers[target]:
                del webrtc_answers[target][username]
            if not webrtc_answers[target]:
                del webrtc_answers[target]
        
        for target in list(webrtc_ice_candidates.keys()):
            if username in webrtc_ice_candidates[target]:
                del webrtc_ice_candidates[target][username]
            if not webrtc_ice_candidates[target]:
                del webrtc_ice_candidates[target]
        
        return JsonResponse({'status': 'cleaned up'})
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

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

def chat_view(request):
    session = get_session(request)
    if not session or 'username' not in session:
        return HttpResponseRedirect('/login')
    
    username = session['username']
    
    if request.method == 'POST':
        form = ChatMessageForm(request.POST, request.FILES)
        if form.is_valid():
            message = form.cleaned_data['message']
            uploaded_file = form.cleaned_data.get('file')
            
            filename = None
            file_url = None
            
            if uploaded_file:
                filename, file_url = save_uploaded_file(uploaded_file)
            
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
        <title>BEAM - Encrypted Messenger</title>
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
                max-width: 100%; 
                margin: 0 auto; 
                padding: 15px;
                color: var(--text-color);
                line-height: 1.6;
            }
            
            .container {
                max-width: 800px;
                margin: 0 auto;
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
            
            .logout-btn {
                background-color: #dc3545;
                color: white;
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                cursor: pointer;
                text-decoration: none;
                font-size: 0.9em;
            }
            
            .logout-btn:hover {
                background-color: #c82333;
            }
            
            h1 {
                text-align: center;
                margin-bottom: 20px;
                color: var(--primary-color);
            }
            
            h2 {
                margin-bottom: 10px;
                color: var(--primary-color);
            }
            
            .security-notice {
                background-color: #e6f7ff;
                border: 1px solid #91d5ff;
                border-radius: 5px;
                padding: 15px;
                margin-bottom: 20px;
            }
            
            .security-notice h3 {
                color: #0050b3;
                margin-top: 0;
            }
            
            .bulletin {
                background-color: var(--secondary-color);
                padding: 15px;
                border: 1px solid var(--border-color);
                border-radius: 5px;
                margin-bottom: 20px;
            }
            
            .chat {
                border: 1px solid var(--border-color);
                border-radius: 5px;
                padding: 10px;
                margin-bottom: 20px;
                max-height: 400px;
                overflow-y: auto;
            }
            
            .message {
                margin-bottom: 10px;
                padding: 10px;
                border-bottom: 1px solid var(--border-color);
            }
            
            .message:last-child {
                border-bottom: none;
            }
            
            .username { 
                font-weight: bold; 
                color: var(--primary-color);
                display: block;
                margin-bottom: 5px;
            }
            
            .timestamp { 
                font-size: 0.8em; 
                color: var(--light-text);
                display: block;
                margin-bottom: 5px;
            }
            
            .file-attachment {
                margin-top: 10px;
                padding: 8px;
                background-color: rgba(51, 102, 204, 0.1);
                border-radius: 4px;
                display: inline-block;
            }
            
            .file-attachment a {
                color: var(--primary-color);
                text-decoration: none;
                display: flex;
                align-items: center;
            }
            
            .file-attachment a:hover {
                text-decoration: underline;
            }
            
            .file-icon {
                margin-right: 5px;
                font-size: 1.2em;
            }
            
            form { 
                margin-top: 20px;
                padding: 15px;
                border: 1px solid var(--border-color);
                border-radius: 5px;
                background-color: var(--secondary-color);
            }
            
            input, textarea, button, .file-input { 
                display: block; 
                margin-bottom: 15px; 
                width: 100%;
                padding: 10px;
                border: 1px solid var(--border-color);
                border-radius: 4px;
                font-family: inherit;
                font-size: 1em;
            }
            
            input:focus, textarea:focus {
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
            
            /* Video call section */
            .video-section {
                margin-top: 30px;
                padding: 20px;
                border: 1px solid var(--border-color);
                border-radius: 5px;
                background-color: var(--secondary-color);
            }
            
            .video-controls {
                display: flex;
                flex-wrap: wrap;
                gap: 10px;
                margin-bottom: 15px;
            }
            
            .video-controls button {
                width: auto;
                padding: 8px 15px;
            }
            
            .video-container {
                display: flex;
                flex-wrap: wrap;
                gap: 15px;
                margin-bottom: 15px;
            }
            
            .video-wrapper {
                flex: 1;
                min-width: 250px;
                border: 1px solid var(--border-color);
                border-radius: 5px;
                overflow: hidden;
                background-color: #000;
            }
            
            .video-wrapper video {
                width: 100%;
                height: auto;
                display: block;
            }
            
            .video-label {
                padding: 5px;
                background-color: rgba(0, 0, 0, 0.5);
                color: white;
                font-size: 0.9em;
                text-align: center;
            }
            
            .call-status {
                margin: 10px 0;
                padding: 8px;
                border-radius: 4px;
                text-align: center;
            }
            
            .calling {
                background-color: #fff3cd;
                color: #856404;
            }
            
            .in-call {
                background-color: #d4edda;
                color: #155724;
            }
            
            .call-ended {
                background-color: #f8d7da;
                color: #721c24;
            }
            
            /* Mobile-first responsive design */
            @media (min-width: 600px) {
                body {
                    padding: 20px;
                }
                
                .message-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 5px;
                }
                
                .username, .timestamp {
                    display: inline;
                    margin-bottom: 0;
                }
                
                .timestamp {
                    margin-left: 10px;
                }
            }
            
            @media (max-width: 599px) {
                h1 {
                    font-size: 1.5em;
                }
                
                h2 {
                    font-size: 1.2em;
                }
                
                .chat {
                    max-height: 300px;
                }
                
                .bulletin, .chat, form {
                    padding: 10px;
                }
                
                .user-header {
                    flex-direction: column;
                    align-items: flex-start;
                }
                
                .user-info {
                    margin-bottom: 10px;
                }
                
                .video-wrapper {
                    min-width: 100%;
                }
            }
            
            /* Dark mode support */
            @media (prefers-color-scheme: dark) {
                :root {
                    --primary-color: #5a8dee;
                    --secondary-color: #2d2d2d;
                    --border-color: #444;
                    --text-color: #f0f0f0;
                    --light-text: #aaa;
                }
                
                body {
                    background-color: #1a1a1a;
                }
                
                .security-notice {
                    background-color: #1a3c5a;
                    border-color: #2a5c8a;
                }
                
                .security-notice h3 {
                    color: #5a8dee;
                }
                
                .file-attachment {
                    background-color: rgba(90, 141, 238, 0.1);
                }
            }
            
            /* API documentation styles */
            .api-section {
                margin-top: 40px;
                padding: 20px;
                border: 1px solid var(--border-color);
                border-radius: 5px;
                background-color: var(--secondary-color);
            }
            
            .endpoint {
                margin-bottom: 15px;
                padding: 10px;
                background-color: rgba(255, 255, 255, 0.1);
                border-left: 4px solid var(--primary-color);
            }
            
            .method {
                display: inline-block;
                padding: 3px 8px;
                border-radius: 3px;
                font-weight: bold;
                margin-right: 10px;
                font-size: 0.8em;
            }
            
            .get { background-color: #61affe; color: white; }
            .post { background-color: #49cc90; color: white; }
            .put { background-color: #fca130; color: white; }
            
            code {
                background-color: rgba(0, 0, 0, 0.1);
                padding: 2px 5px;
                border-radius: 3px;
                font-family: monospace;
            }
            
            pre {
                background-color: rgba(0, 0, 0, 0.1);
                padding: 10px;
                border-radius: 5px;
                overflow-x: auto;
                margin: 10px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="user-header">
                <div class="user-info">
                    <span class="welcome">Welcome, {{ username }}!</span>
                </div>
                <a href="/logout" class="logout-btn">Logout</a>
            </div>
            
            <h1>BEAM - Encrypted Messenger</h1>
            
            <div class="security-notice">
                <h3>🔒 End-to-End Encryption</h3>
                <p>All messages are encrypted using AES-128 encryption before being stored. 
                Your conversations are secure and private.</p>
            </div>
            
            <div class="bulletin">
                <h2>Bulletin Board</h2>
                <p>{{ bulletin_content|linebreaks }}</p>
            </div>
            
            <h2>Chat</h2>
            <div class="chat">
                {% for msg in messages %}
                <div class="message">
                    <div class="message-header">
                        <span class="username">{{ msg.username }}</span>
                        <span class="timestamp">{{ msg.timestamp }}</span>
                    </div>
                    <p>{{ msg.message }}</p>
                    {% if msg.filename and msg.file_url %}
                    <div class="file-attachment">
                        <a href="{{ msg.file_url }}" target="_blank">
                            <span class="file-icon">📎</span>
                            {{ msg.filename }}
                        </a>
                    </div>
                    {% endif %}
                </div>
                {% empty %}
                <p>No messages yet. Be the first to chat!</p>
                {% endfor %}
            </div>
            
            <form method="post" enctype="multipart/form-data">
                {% csrf_token %}
                <textarea name="message" placeholder="Your message" rows="3"></textarea>
                <div class="file-input">
                    <label for="file">Attach a file (optional):</label>
                    <input type="file" name="file" id="file">
                </div>
                <button type="submit">Send Message</button>
            </form>
            
            <!-- Video Call Section -->
            <div class="video-section">
                <h2>Video Calls</h2>
                <p>Start a secure video call with another user. All calls are peer-to-peer and encrypted.</p>
                
                <div class="video-controls">
                    <input type="text" id="callUsername" placeholder="Username to call">
                    <button id="startCall">Start Call</button>
                    <button id="endCall" disabled>End Call</button>
                    <button id="shareScreen">Share Screen</button>
                    <button id="stopScreen" disabled>Stop Screen</button>
                </div>
                
                <div id="callStatus" class="call-status"></div>
                
                <div class="video-container">
                    <div class="video-wrapper">
                        <div class="video-label">Your Video</div>
                        <video id="localVideo" autoplay muted playsinline></video>
                    </div>
                    <div class="video-wrapper">
                        <div class="video-label">Remote Video</div>
                        <video id="remoteVideo" autoplay playsinline></video>
                    </div>
                </div>
            </div>
            
            <div class="api-section">
                <h2>API Documentation</h2>
                <p>Programmatic access to the chat and bulletin board:</p>
                
                <div class="endpoint">
                    <span class="method get">GET</span>
                    <code>/api/chat/</code>
                    <p>Retrieve all chat messages as JSON.</p>
                </div>
                
                <div class="endpoint">
                    <span class="method post">POST</span>
                    <code>/api/chat/</code>
                    <p>Post a new chat message. Requires JSON body with "username" and "message".</p>
                    <pre>
{
    "username": "your_username",
    "message": "your_message"
}</pre>
                </div>
                
                <div class="endpoint">
                    <span class="method get">GET</span>
                    <code>/api/bulletin/</code>
                    <p>Retrieve the current bulletin board content.</p>
                </div>
                
                <div class="endpoint">
                    <span class="method put">PUT</span>
                    <code>/api/bulletin/</code>
                    <p>Update the bulletin board content. Requires JSON body with "content".</p>
                    <pre>
{
    "content": "New bulletin content"
}</pre>
                </div>
                
                <div class="endpoint">
                    <span class="method post">POST</span>
                    <code>/api/upload/</code>
                    <p>Upload a file. Requires multipart/form-data with "file" field.</p>
                </div>
                
                <div class="endpoint">
                    <span class="method get">GET</span>
                    <code>/download/&lt;filename&gt;</code>
                    <p>Download an uploaded file.</p>
                </div>
                
                <div class="endpoint">
                    <span class="method post">POST</span>
                    <code>/api/webrtc/offer/</code>
                    <p>Send WebRTC offer to a user.</p>
                </div>
                
                <div class="endpoint">
                    <span class="method get">GET</span>
                    <code>/api/webrtc/offer/&lt;username&gt;</code>
                    <p>Get WebRTC offers for a user.</p>
                </div>
                
                <div class="endpoint">
                    <span class="method post">POST</span>
                    <code>/api/webrtc/answer/</code>
                    <p>Send WebRTC answer to a user.</p>
                </div>
                
                <div class="endpoint">
                    <span class="method get">GET</span>
                    <code>/api/webrtc/answer/&lt;username&gt;</code>
                    <p>Get WebRTC answers for a user.</p>
                </div>
                
                <div class="endpoint">
                    <span class="method post">POST</span>
                    <code>/api/webrtc/ice/</code>
                    <p>Send ICE candidate to a user.</p>
                </div>
                
                <div class="endpoint">
                    <span class="method get">GET</span>
                    <code>/api/webrtc/ice/&lt;username&gt;</code>
                    <p>Get ICE candidates for a user.</p>
                </div>
            </div>
        </div>
        
        <script>
            // WebRTC video call functionality
            const localVideo = document.getElementById('localVideo');
            const remoteVideo = document.getElementById('remoteVideo');
            const startCallButton = document.getElementById('startCall');
            const endCallButton = document.getElementById('endCall');
            const shareScreenButton = document.getElementById('shareScreen');
            const stopScreenButton = document.getElementById('stopScreen');
            const callUsernameInput = document.getElementById('callUsername');
            const callStatus = document.getElementById('callStatus');
            
            let localStream = null;
            let remoteStream = null;
            let peerConnection = null;
            let screenStream = null;
            let isCalling = false;
            let currentCallTarget = null;
            const configuration = {
                iceServers: [
                    { urls: 'stun:stun.l.google.com:19302' },
                    { urls: 'stun:stun1.l.google.com:19302' }
                ]
            };
            
            // Initialize media devices
            async function initMedia() {
                try {
                    localStream = await navigator.mediaDevices.getUserMedia({ 
                        video: true, 
                        audio: true 
                    });
                    localVideo.srcObject = localStream;
                } catch (error) {
                    console.error('Error accessing media devices:', error);
                    callStatus.textContent = 'Cannot access camera/microphone. Please check permissions.';
                    callStatus.className = 'call-status call-ended';
                }
            }
            
            // Create peer connection
            function createPeerConnection() {
                peerConnection = new RTCPeerConnection(configuration);
                
                // Add local stream to connection
                localStream.getTracks().forEach(track => {
                    peerConnection.addTrack(track, localStream);
                });
                
                // Handle remote stream
                peerConnection.ontrack = (event) => {
                    remoteStream = event.streams[0];
                    remoteVideo.srcObject = remoteStream;
                };
                
                // Handle ICE candidates
                peerConnection.onicecandidate = (event) => {
                    if (event.candidate) {
                        // Send ICE candidate to the other user
                        fetch('/api/webrtc/ice/', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                username: '{{ username }}',
                                target: currentCallTarget,
                                candidate: event.candidate
                            })
                        });
                    }
                };
                
                // Handle connection state changes
                peerConnection.onconnectionstatechange = () => {
                    switch(peerConnection.connectionState) {
                        case 'connected':
                            callStatus.textContent = 'Call connected';
                            callStatus.className = 'call-status in-call';
                            break;
                        case 'disconnected':
                        case 'failed':
                            endCall();
                            break;
                        case 'closed':
                            endCall();
                            break;
                    }
                };
            }
            
            // Start a call
            async function startCall() {
                const targetUsername = callUsernameInput.value.trim();
                if (!targetUsername) {
                    callStatus.textContent = 'Please enter a username to call';
                    callStatus.className = 'call-status call-ended';
                    return;
                }
                
                if (targetUsername === '{{ username }}') {
                    callStatus.textContent = 'You cannot call yourself';
                    callStatus.className = 'call-status call-ended';
                    return;
                }
                
                currentCallTarget = targetUsername;
                isCalling = true;
                callStatus.textContent = `Calling ${targetUsername}...`;
                callStatus.className = 'call-status calling';
                
                startCallButton.disabled = true;
                endCallButton.disabled = false;
                callUsernameInput.disabled = true;
                
                createPeerConnection();
                
                try {
                    // Create offer
                    const offer = await peerConnection.createOffer();
                    await peerConnection.setLocalDescription(offer);
                    
                    // Send offer to the other user
                    await fetch('/api/webrtc/offer/', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            username: '{{ username }}',
                            target: targetUsername,
                            offer: offer
                        })
                    });
                    
                    // Start checking for answers
                    checkForAnswer();
                } catch (error) {
                    console.error('Error creating offer:', error);
                    callStatus.textContent = 'Error starting call';
                    callStatus.className = 'call-status call-ended';
                    endCall();
                }
            }
            
            // Check for answer from the other user
            async function checkForAnswer() {
                if (!isCalling) return;
                
                try {
                    const response = await fetch(`/api/webrtc/answer/{{ username }}`);
                    const data = await response.json();
                    
                    if (data.answers && data.answers[currentCallTarget]) {
                        const answer = data.answers[currentCallTarget];
                        await peerConnection.setRemoteDescription(answer);
                        
                        // Stop checking once we have the answer
                        return;
                    }
                    
                    // Keep checking every 2 seconds
                    setTimeout(checkForAnswer, 2000);
                } catch (error) {
                    console.error('Error checking for answer:', error);
                    setTimeout(checkForAnswer, 2000);
                }
            }
            
            // End the call
            function endCall() {
                isCalling = false;
                currentCallTarget = null;
                
                if (peerConnection) {
                    peerConnection.close();
                    peerConnection = null;
                }
                
                if (screenStream) {
                    screenStream.getTracks().forEach(track => track.stop());
                    screenStream = null;
                }
                
                // Switch back to camera if screen was sharing
                if (localStream) {
                    localVideo.srcObject = localStream;
                } else {
                    localVideo.srcObject = null;
                }
                
                remoteVideo.srcObject = null;
                
                startCallButton.disabled = false;
                endCallButton.disabled = true;
                shareScreenButton.disabled = false;
                stopScreenButton.disabled = true;
                callUsernameInput.disabled = false;
                
                callStatus.textContent = 'Call ended';
                callStatus.className = 'call-status call-ended';
                
                // Clean up signaling data
                fetch('/api/webrtc/cleanup/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username: '{{ username }}'
                    })
                });
            }
            
            // Share screen
            async function shareScreen() {
                try {
                    screenStream = await navigator.mediaDevices.getDisplayMedia({
                        video: true,
                        audio: true
                    });
                    
                    // Replace the video track in the peer connection
                    const videoTrack = screenStream.getVideoTracks()[0];
                    const sender = peerConnection.getSenders().find(
                        s => s.track && s.track.kind === 'video'
                    );
                    
                    if (sender) {
                        await sender.replaceTrack(videoTrack);
                    }
                    
                    // Update local video display
                    localVideo.srcObject = screenStream;
                    
                    shareScreenButton.disabled = true;
                    stopScreenButton.disabled = false;
                    
                    // Handle when the user stops screen sharing
                    videoTrack.onended = () => {
                        stopScreenSharing();
                    };
                } catch (error) {
                    console.error('Error sharing screen:', error);
                }
            }
            
            // Stop screen sharing
            async function stopScreenSharing() {
                if (screenStream) {
                    screenStream.getTracks().forEach(track => track.stop());
                    screenStream = null;
                }
                
                // Switch back to camera
                if (localStream) {
                    const videoTrack = localStream.getVideoTracks()[0];
                    const sender = peerConnection.getSenders().find(
                        s => s.track && s.track.kind === 'video'
                    );
                    
                    if (sender && videoTrack) {
                        await sender.replaceTrack(videoTrack);
                    }
                    
                    localVideo.srcObject = localStream;
                }
                
                shareScreenButton.disabled = false;
                stopScreenButton.disabled = true;
            }
            
            // Check for incoming calls
            async function checkForIncomingCalls() {
                try {
                    const response = await fetch(`/api/webrtc/offer/{{ username }}`);
                    const data = await response.json();
                    
                    if (data.offers && Object.keys(data.offers).length > 0) {
                        for (const [caller, offer] of Object.entries(data.offers)) {
                            if (!isCalling) {
                                const acceptCall = confirm(`${caller} is calling you. Accept?`);
                                
                                if (acceptCall) {
                                    currentCallTarget = caller;
                                    isCalling = true;
                                    callStatus.textContent = `In call with ${caller}`;
                                    callStatus.className = 'call-status in-call';
                                    
                                    startCallButton.disabled = true;
                                    endCallButton.disabled = false;
                                    callUsernameInput.disabled = true;
                                    
                                    createPeerConnection();
                                    
                                    await peerConnection.setRemoteDescription(offer);
                                    const answer = await peerConnection.createAnswer();
                                    await peerConnection.setLocalDescription(answer);
                                    
                                    // Send answer back to caller
                                    await fetch('/api/webrtc/answer/', {
                                        method: 'POST',
                                        headers: {
                                            'Content-Type': 'application/json',
                                        },
                                        body: JSON.stringify({
                                            username: '{{ username }}',
                                            target: caller,
                                            answer: answer
                                        })
                                    });
                                    
                                    // Check for ICE candidates from the caller
                                    checkForICECandidates();
                                }
                                
                                // Remove the offer regardless of acceptance
                                await fetch('/api/webrtc/offer/', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                    },
                                    body: JSON.stringify({
                                        username: '{{ username }}',
                                        target: caller,
                                        offer: null
                                    })
                                });
                            }
                        }
                    }
                    
                    // Keep checking for incoming calls
                    setTimeout(checkForIncomingCalls, 3000);
                } catch (error) {
                    console.error('Error checking for incoming calls:', error);
                    setTimeout(checkForIncomingCalls, 3000);
                }
            }
            
            // Check for ICE candidates from the other user
            async function checkForICECandidates() {
                if (!isCalling) return;
                
                try {
                    const response = await fetch(`/api/webrtc/ice/{{ username }}`);
                    const data = await response.json();
                    
                    if (data.candidates && data.candidates[currentCallTarget]) {
                        const candidates = data.candidates[currentCallTarget];
                        
                        for (const candidate of candidates) {
                            await peerConnection.addIceCandidate(candidate);
                        }
                        
                        // Clear the candidates after processing
                        await fetch('/api/webrtc/ice/', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                username: '{{ username }}',
                                target: currentCallTarget,
                                candidate: null
                            })
                        });
                    }
                    
                    // Keep checking for ICE candidates while in call
                    if (isCalling) {
                        setTimeout(checkForICECandidates, 2000);
                    }
                } catch (error) {
                    console.error('Error checking for ICE candidates:', error);
                    if (isCalling) {
                        setTimeout(checkForICECandidates, 2000);
                    }
                }
            }
            
            // Event listeners
            startCallButton.addEventListener('click', startCall);
            endCallButton.addEventListener('click', endCall);
            shareScreenButton.addEventListener('click', shareScreen);
            stopScreenButton.addEventListener('click', stopScreenSharing);
            
            // Initialize
            initMedia();
            checkForIncomingCalls();
        </script>
    </body>
    </html>
    ''')
    
    context = Context({
        'username': username,
        'messages': messages,
        'bulletin_content': bulletin_content,
        'bulletin_file': BULLETIN_FILE
    })
    
    return HttpResponse(template.render(context))

def download_file(request, filename):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
    else:
        return HttpResponse('File not found', status=404)

# API Views
@csrf_exempt
@require_http_methods(["GET", "POST"])
def api_chat(request):
    if request.method == 'GET':
        # Return all chat messages
        messages = read_chat_messages()
        return JsonResponse({'messages': messages})
    
    elif request.method == 'POST':
        # Create a new chat message
        try:
            # Check if it's a form data request (with file) or JSON request
            if request.content_type.startswith('multipart/form-data'):
                username = request.POST.get('username')
                message = request.POST.get('message', '')
                uploaded_file = request.FILES.get('file')
                
                filename = None
                file_url = None
                
                if uploaded_file:
                    filename, file_url = save_uploaded_file(uploaded_file)
                
                saved_message = save_chat_message(username, message, filename, file_url)
                return JsonResponse(saved_message, status=201)
            else:
                # JSON request
                data = json.loads(request.body)
                username = data.get('username')
                message = data.get('message')
                
                if not username:
                    return JsonResponse(
                        {'error': 'Username is required'}, 
                        status=400
                    )
                
                saved_message = save_chat_message(username, message)
                return JsonResponse(saved_message, status=201)
        except json.JSONDecodeError:
            return JsonResponse(
                {'error': 'Invalid JSON'}, 
                status=400
            )

@csrf_exempt
@require_http_methods(["GET", "PUT"])
def api_bulletin(request):
    if request.method == 'GET':
        # Return bulletin content
        content = read_bulletin()
        return JsonResponse({'content': content})
    
    elif request.method == 'PUT':
        # Update bulletin content
        try:
            data = json.loads(request.body)
            content = data.get('content', '')
            
            updated_content = write_bulletin(content)
            return JsonResponse({'content': updated_content})
        except json.JSONDecodeError:
            return JsonResponse(
                {'error': 'Invalid JSON'}, 
                status=400
            )

@csrf_exempt
@require_http_methods(["POST"])
def api_upload(request):
    # API endpoint for file uploads
    if 'file' not in request.FILES:
        return JsonResponse({'error': 'No file provided'}, status=400)
    
    uploaded_file = request.FILES['file']
    filename, file_url = save_uploaded_file(uploaded_file)
    
    return JsonResponse({
        'filename': filename,
        'url': file_url
    }, status=201)

# URL patterns
urlpatterns = [
    path('', chat_view, name='home'),
    path('login/', login_view, name='login'),
    path('login', login_view),
    path('register/', register_view, name='register'),
    path('register', register_view),
    path('logout/', logout_view, name='logout'),
    path('logout', logout_view),
    path('api/chat/', api_chat),
    path('api/bulletin/', api_bulletin),
    path('api/upload/', api_upload),
    path('download/<str:filename>', download_file),
    # WebRTC signaling endpoints
    path('api/webrtc/offer/', webrtc_offer),
    path('api/webrtc/offer/<str:username>', webrtc_get_offer),
    path('api/webrtc/answer/', webrtc_answer),
    path('api/webrtc/answer/<str:username>', webrtc_get_answer),
    path('api/webrtc/ice/', webrtc_ice_candidate),
    path('api/webrtc/ice/<str:username>', webrtc_get_ice_candidates),
    path('api/webrtc/cleanup/', webrtc_cleanup),
]

# Application object
application = get_wsgi_application()

# Run the application
if __name__ == '__main__':
    import sys
    from django.core.management import execute_from_command_line
    
    # Start localtunnel if enabled
    start_localtunnel()
    
    # Check if we're running with the runserver command
    if len(sys.argv) > 1 and sys.argv[1] == 'runserver':
        execute_from_command_line(sys.argv)
    else:
        # Default to running the server
        print("Starting Django server...")
        print(f"Chat messages stored in: {os.path.abspath(CHAT_FILE)}")
        print(f"Bulletin board stored in: {os.path.abspath(BULLETIN_FILE)}")
        print(f"User data stored in: {os.path.abspath(USERS_FILE)}")
        print(f"Uploaded files stored in: {os.path.abspath(UPLOAD_DIR)}")
        print(f"Encryption key stored in: {os.path.abspath(ENCRYPTION_KEY_FILE)}")
        print("🔒 All messages and user data are encrypted using AES-128 encryption")
        print("To update the bulletin board, edit the bulletin_board.txt file")
        
        if USE_LOCALTUNNEL:
            print("\nLocaltunnel is enabled. It will start automatically.")
            print("If localtunnel is not installed, you can install it with:")
            print("npm install -g localtunnel")
        else:
            print("\nLocaltunnel is disabled. To enable it, set USE_LOCALTUNNEL = True")
        
        print("\nAPI endpoints available:")
        print("GET  /api/chat/     - Retrieve all chat messages")
        print("POST /api/chat/     - Post a new chat message")
        print("GET  /api/bulletin/ - Retrieve bulletin content")
        print("PUT  /api/bulletin/ - Update bulletin content")
        print("POST /api/upload/   - Upload a file")
        print("GET  /download/<filename> - Download a file")
        print("\nWebRTC signaling endpoints:")
        print("POST /api/webrtc/offer/ - Send WebRTC offer")
        print("GET  /api/webrtc/offer/<username> - Get WebRTC offers")
        print("POST /api/webrtc/answer/ - Send WebRTC answer")
        print("GET  /api/webrtc/answer/<username> - Get WebRTC answers")
        print("POST /api/webrtc/ice/ - Send ICE candidate")
        print("GET  /api/webrtc/ice/<username> - Get ICE candidates")
        print("POST /api/webrtc/cleanup/ - Clean up signaling data")
        
        execute_from_command_line(['manage.py', 'runserver', '0.0.0.0:8000'])
