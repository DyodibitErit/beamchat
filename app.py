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
    # Увеличим максимальный размер загружаемых файлов (10 МБ)
    DATA_UPLOAD_MAX_MEMORY_SIZE = 50 * 1024 * 1024,
)

# Message storage files
CHAT_FILE = 'chat_messages.txt'
BULLETIN_FILE = 'bulletin_board.txt'
UPLOAD_DIR = 'uploads'

# Ensure files and directories exist
for file in [CHAT_FILE, BULLETIN_FILE]:
    if not os.path.exists(file):
        with open(file, 'w') as f:
            f.write('')

# Create upload directory if it doesn't exist
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

# Forms
class ChatMessageForm(forms.Form):
    username = forms.CharField(max_length=50)
    message = forms.CharField(widget=forms.Textarea, required=False)
    file = forms.FileField(required=False)

# Utility functions
def read_chat_messages():
    messages = []
    try:
        with open(CHAT_FILE, 'r', encoding="UTF-8") as f:
            for line in f:
                if line.strip():
                    messages.append(json.loads(line))
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return messages

def save_chat_message(username, message, filename=None, file_url=None):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    message_data = {
        'username': username,
        'message': message,
        'timestamp': timestamp
    }
    
    if filename and file_url:
        message_data['filename'] = filename
        message_data['file_url'] = file_url
    
    with open(CHAT_FILE, 'a', encoding="UTF-8") as f:
        f.write(json.dumps(message_data) + '\n')
    return message_data

def read_bulletin():
    try:
        with open(BULLETIN_FILE, 'r', encoding="UTF-8") as f:
            return f.read()
    except FileNotFoundError:
        return "Bulletin board is empty."

def write_bulletin(content):
    with open(BULLETIN_FILE, 'w', encoding="UTF-8") as f:
        f.write(content)
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

# Views
def chat_view(request):
    if request.method == 'POST':
        form = ChatMessageForm(request.POST, request.FILES)
        if form.is_valid():
            username = form.cleaned_data['username']
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
        <title>BEAM</title>
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
            
            h1 {
                text-align: center;
                margin-bottom: 20px;
                color: var(--primary-color);
            }
            
            h2 {
                margin-bottom: 10px;
                color: var(--primary-color);
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
            <h1>BEAM</h1>
            
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
                <input type="text" name="username" placeholder="Your name" required>
                <textarea name="message" placeholder="Your message" rows="3"></textarea>
                <div class="file-input">
                    <label for="file">Attach a file (optional):</label>
                    <input type="file" name="file" id="file">
                </div>
                <button type="submit">Send Message</button>
            </form>
            
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
            </div>
        </div>
    </body>
    </html>
    ''')
    
    context = Context({
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
    path('', chat_view),
    path('api/chat/', api_chat),
    path('api/bulletin/', api_bulletin),
    path('api/upload/', api_upload),
    path('download/<str:filename>', download_file),
]

# Application object
application = get_wsgi_application()

# Run the application
if __name__ == '__main__':
    import sys
    from django.core.management import execute_from_command_line
    
    # Check if we're running with the runserver command
    if len(sys.argv) > 1 and sys.argv[1] == 'runserver':
        execute_from_command_line(sys.argv)
    else:
        # Default to running the server
        print("Starting Django server...")
        print(f"Chat messages stored in: {os.path.abspath(CHAT_FILE)}")
        print(f"Bulletin board stored in: {os.path.abspath(BULLETIN_FILE)}")
        print(f"Uploaded files stored in: {os.path.abspath(UPLOAD_DIR)}")
        print("To update the bulletin board, edit the bulletin_board.txt file")
        print("\nTo expose your server to the internet, install localtunnel:")
        print("npm install -g localtunnel")
        print("Then run: lt --port 8000")
        print("\nAPI endpoints available:")
        print("GET  /api/chat/     - Retrieve all chat messages")
        print("POST /api/chat/     - Post a new chat message")
        print("GET  /api/bulletin/ - Retrieve bulletin content")
        print("PUT  /api/bulletin/ - Update bulletin content")
        print("POST /api/upload/   - Upload a file")
        print("GET  /download/<filename> - Download a file")
        
        execute_from_command_line(['manage.py', 'runserver', '0.0.0.0:8000'])