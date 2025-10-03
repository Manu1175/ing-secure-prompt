"""
SecurePrompt - Combined Application
Complete working version with advanced scrubbing + ING UI
"""
from flask import Flask, render_template_string, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import hashlib
import os

# Import our advanced scrubbing components
from scrubber import Scrubber
from descrubber import DeScrubber, AccessControlPolicy
from audit import AuditLogger, MetricsObserver, AlertObserver
from pathlib import Path

# ============================================================================
# FLASK APP CONFIGURATION
# ============================================================================

basedir = os.path.abspath(os.path.dirname(__file__))

BASEDIR = Path(__file__).resolve().parents[2]

CONFIG_DIR = BASEDIR / "config"

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'test-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'secureprompt.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize advanced scrubbing components
audit_logger = AuditLogger(os.path.join(basedir, 'audit_events.jsonl'))
metrics_observer = MetricsObserver()
alert_observer = AlertObserver(alert_threshold=10)

audit_logger.register_observer(metrics_observer)
audit_logger.register_observer(alert_observer)

# Initialize scrubber with advanced features
scrubber = Scrubber(
    rules_yaml=CONFIG_DIR/"rules.yaml",
    whitelist_yaml=CONFIG_DIR/"whitelist.yaml",
    fpe_key=os.environ.get('FPE_KEY', 'default-key-change-in-production-32bytes!'),
    audit_logger=audit_logger
)

descrubber = DeScrubber(
    audit_logger=audit_logger,
    access_policy=AccessControlPolicy()
)

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(UserMixin, db.Model):
    """User model."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='data_analyst')  # Role for access control
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ScrubSession(db.Model):
    """Scrubbing session with advanced tracking."""
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(32), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    original_prompt = db.Column(db.Text, nullable=False)
    scrubbed_prompt = db.Column(db.Text, nullable=False)
    entity_count = db.Column(db.Integer, default=0)
    confidence_score = db.Column(db.Float)
    entities_json = db.Column(db.Text)  # Store entities as JSON
    audit_event_id = db.Column(db.String(100))  # Link to audit log
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ============================================================================
# HTML TEMPLATES (From working_app.py - keeping ING branding)
# ============================================================================

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - SecurePrompt | ING</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-blue-500 to-purple-600 min-h-screen flex items-center justify-center">
    <div class="bg-white rounded-lg shadow-2xl p-8 w-full max-w-md">
        <div class="text-center mb-8">
            <h1 class="text-4xl font-bold text-gray-800">🔐 SecurePrompt</h1>
            <p class="text-gray-600 mt-2">Banking LLM Security System</p>
        </div>

        <form id="loginForm" onsubmit="handleLogin(event)">
            <div class="mb-4">
                <label class="block text-gray-700 font-semibold mb-2">Username</label>
                <input 
                    type="text" 
                    id="username"
                    value="admin"
                    class="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="admin"
                    required
                >
            </div>

            <div class="mb-6">
                <label class="block text-gray-700 font-semibold mb-2">Password</label>
                <input 
                    type="password" 
                    id="password"
                    value="admin123"
                    class="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="admin123"
                    required
                >
            </div>

            <div id="errorMsg" class="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded hidden">
                <p id="errorText"></p>
            </div>

            <button 
                type="submit"
                id="loginBtn"
                class="w-full bg-blue-600 text-white font-semibold py-3 rounded-lg hover:bg-blue-700 transition"
            >
                Login
            </button>
        </form>

        <p class="text-center mt-6 text-gray-600">
            Don't have an account? 
            <a href="/register" class="text-blue-600 hover:underline font-semibold">Register</a>
        </p>

        <div class="mt-6 p-4 bg-blue-50 rounded border border-blue-200">
            <p class="text-sm text-blue-800">
                <strong>Test Credentials:</strong><br>
                Username: admin<br>
                Password: admin123
            </p>
        </div>
    </div>

    <script>
        async function handleLogin(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const loginBtn = document.getElementById('loginBtn');
            const errorMsg = document.getElementById('errorMsg');
            const errorText = document.getElementById('errorText');
            
            loginBtn.disabled = true;
            loginBtn.textContent = 'Logging in...';
            errorMsg.classList.add('hidden');
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                if (response.ok) {
                    window.location.href = '/';
                } else {
                    const data = await response.json();
                    errorText.textContent = data.error || 'Login failed';
                    errorMsg.classList.remove('hidden');
                }
            } catch (error) {
                errorText.textContent = 'Network error. Please try again.';
                errorMsg.classList.remove('hidden');
            } finally {
                loginBtn.disabled = false;
                loginBtn.textContent = 'Login';
            }
        }
    </script>
</body>
</html>
"""

# Import dashboard and other templates from working_app.py
# (Keeping them as-is but updating the scrubbing logic)

DASHBOARD_HTML = open('app_.py').read().split('DASHBOARD_HTML = """')[1].split('"""')[0] if os.path.exists('app_.py') else """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - SecurePrompt</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50">
    <nav class="bg-orange-600 shadow-lg">
        <div class="max-w-7xl mx-auto px-6 py-4">
            <div class="flex justify-between items-center">
                <div>
                    <h1 class="text-white text-xl font-bold">SecurePrompt</h1>
                    <p class="text-orange-100 text-xs">Advanced LLM Data Protection</p>
                </div>
                
                <div class="flex space-x-4">
                    <a href="/" class="text-white hover:text-orange-100">Dashboard</a>
                    <a href="/history" class="text-white hover:text-orange-100">History</a>
                    <a href="/metrics" class="text-white hover:text-orange-100">Metrics</a>
                    <button onclick="logout()" class="bg-white text-orange-600 px-4 py-2 rounded">Logout</button>
                </div>
            </div>
        </div>
    </nav>

    <div class="max-w-7xl mx-auto px-6 py-8">
        <div class="grid grid-cols-2 gap-6">
            <!-- Input -->
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-xl font-bold mb-4">Original Prompt</h3>
                <textarea 
                    id="promptInput"
                    class="w-full h-64 p-4 border rounded resize-none"
                    placeholder="Enter your prompt here..."
                ></textarea>
                <button 
                    onclick="scrubPrompt()"
                    class="mt-4 w-full bg-orange-600 text-white py-3 rounded font-bold hover:bg-orange-700"
                >
                    Secure & Scrub
                </button>
            </div>

            <!-- Output -->
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-xl font-bold mb-4">Secured Prompt</h3>
                <div id="noResult" class="h-64 flex items-center justify-center border-2 border-dashed rounded">
                    <p class="text-gray-400">Secured content will appear here</p>
                </div>
                <div id="result" class="hidden">
                    <div class="h-64 p-4 bg-green-50 border rounded overflow-auto mb-4">
                        <pre id="scrubbedContent" class="text-sm whitespace-pre-wrap"></pre>
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="bg-orange-500 text-white p-4 rounded">
                            <p class="text-xs mb-1">Entities</p>
                            <p id="entityCount" class="text-2xl font-bold">0</p>
                        </div>
                        <div class="bg-green-500 text-white p-4 rounded">
                            <p class="text-xs mb-1">Confidence</p>
                            <p id="confidence" class="text-2xl font-bold">0%</p>
                        </div>
                    </div>
                    <div id="entitiesList" class="mt-4"></div>
                </div>
            </div>
        </div>

        <div id="error" class="hidden mt-6 bg-red-50 border-l-4 border-red-500 p-4">
            <p id="errorText" class="text-red-700"></p>
        </div>
    </div>

    <script>
        async function scrubPrompt() {
            const prompt = document.getElementById('promptInput').value;
            if (!prompt.trim()) {
                showError('Please enter a prompt');
                return;
            }

            try {
                const response = await fetch('/api/scrub', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ prompt })
                });

                if (response.ok) {
                    const data = await response.json();
                    displayResult(data);
                } else {
                    const data = await response.json();
                    showError(data.error || 'Scrubbing failed');
                }
            } catch (err) {
                showError('Network error');
            }
        }

        function displayResult(data) {
            document.getElementById('noResult').classList.add('hidden');
            document.getElementById('result').classList.remove('hidden');
            
            document.getElementById('scrubbedContent').textContent = data.scrubbed_content;
            document.getElementById('entityCount').textContent = data.entity_count;
            document.getElementById('confidence').textContent = Math.round(data.confidence_score * 100) + '%';
            
            const entitiesList = document.getElementById('entitiesList');
            if (data.entities && data.entities.length > 0) {
                let html = '<h4 class="font-bold mb-2">Detected Entities:</h4><div class="space-y-2">';
                data.entities.forEach(entity => {
                    html += `
                        <div class="flex justify-between p-3 bg-blue-50 border rounded">
                            <span class="font-mono text-sm">${entity.id}</span>
                            <span class="text-xs px-2 py-1 bg-white rounded">${entity.entity}</span>
                            <span class="text-xs font-bold">${Math.round(entity.confidence * 100)}%</span>
                        </div>
                    `;
                });
                html += '</div>';
                entitiesList.innerHTML = html;
            }
        }

        function showError(message) {
            const error = document.getElementById('error');
            document.getElementById('errorText').textContent = message;
            error.classList.remove('hidden');
            setTimeout(() => error.classList.add('hidden'), 5000);
        }

        async function logout() {
            const response = await fetch('/api/logout', { method: 'POST' });
            if (response.ok) window.location.href = '/login';
        }
    </script>
</body>
</html>
"""

REGISTER_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - SecurePrompt</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gradient-to-br from-blue-500 to-purple-600 min-h-screen flex items-center justify-center">
    <div class="bg-white rounded-lg shadow-2xl p-8 w-full max-w-md">
        <h1 class="text-3xl font-bold text-center mb-8">Create Account</h1>
        <form id="registerForm" onsubmit="handleRegister(event)">
            <div class="mb-4">
                <label class="block text-gray-700 font-semibold mb-2">Username</label>
                <input type="text" id="username" class="w-full px-4 py-2 border rounded-lg" required>
            </div>
            <div class="mb-4">
                <label class="block text-gray-700 font-semibold mb-2">Email</label>
                <input type="email" id="email" class="w-full px-4 py-2 border rounded-lg" required>
            </div>
            <div class="mb-6">
                <label class="block text-gray-700 font-semibold mb-2">Password</label>
                <input type="password" id="password" class="w-full px-4 py-2 border rounded-lg" required>
            </div>
            <button type="submit" class="w-full bg-blue-600 text-white py-3 rounded-lg hover:bg-blue-700">
                Register
            </button>
        </form>
        <p class="text-center mt-6">
            <a href="/login" class="text-blue-600 hover:underline">Back to Login</a>
        </p>
    </div>
    <script>
        async function handleRegister(e) {
            e.preventDefault();
            const data = {
                username: document.getElementById('username').value,
                email: document.getElementById('email').value,
                password: document.getElementById('password').value
            };
            const response = await fetch('/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            if (response.ok) {
                alert('Registration successful!');
                window.location.href = '/login';
            } else {
                const result = await response.json();
                alert(result.error || 'Registration failed');
            }
        }
    </script>
</body>
</html>
"""

HISTORY_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>History - SecurePrompt</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50">
    <nav class="bg-orange-600 shadow-lg">
        <div class="max-w-7xl mx-auto px-6 py-4">
            <div class="flex justify-between items-center">
                <h1 class="text-white text-xl font-bold">SecurePrompt - History</h1>
                <div class="flex space-x-4">
                    <a href="/" class="text-white hover:text-orange-100">Dashboard</a>
                    <button onclick="logout()" class="bg-white text-orange-600 px-4 py-2 rounded">Logout</button>
                </div>
            </div>
        </div>
    </nav>
    <div class="max-w-7xl mx-auto py-8 px-4">
        <div class="bg-white rounded-lg shadow p-6">
            <h2 class="text-2xl font-bold mb-6">Scrubbing History</h2>
            {% if sessions %}
            <div class="space-y-4">
                {% for session in sessions %}
                <div class="border rounded p-4 hover:bg-gray-50">
                    <p class="text-sm text-gray-600 mb-2">{{ session.created_at.strftime('%Y-%m-%d %H:%M:%S') }}</p>
                    <p class="text-gray-800 mb-2">{{ session.scrubbed_prompt[:200] }}...</p>
                    <div class="flex gap-4 text-sm">
                        <span class="text-blue-600">{{ session.entity_count }} entities</span>
                        <span class="text-green-600">{{ (session.confidence_score * 100)|round }}% confidence</span>
                    </div>
                </div>
                {% endfor %}
            </div>
            {% else %}
            <p class="text-center text-gray-500 py-12">No history yet</p>
            {% endif %}
        </div>
    </div>
    <script>
        async function logout() {
            await fetch('/api/logout', { method: 'POST' });
            window.location.href = '/login';
        }
    </script>
</body>
</html>
"""

METRICS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Metrics - SecurePrompt</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50">
    <nav class="bg-orange-600 shadow-lg">
        <div class="max-w-7xl mx-auto px-6 py-4">
            <div class="flex justify-between items-center">
                <h1 class="text-white text-xl font-bold">SecurePrompt - Metrics</h1>
                <div class="flex space-x-4">
                    <a href="/" class="text-white hover:text-orange-100">Dashboard</a>
                    <a href="/history" class="text-white hover:text-orange-100">History</a>
                    <button onclick="logout()" class="bg-white text-orange-600 px-4 py-2 rounded">Logout</button>
                </div>
            </div>
        </div>
    </nav>
    <div class="max-w-7xl mx-auto py-8 px-4">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-gray-600 text-sm mb-2">Total Scrubs</h3>
                <p class="text-4xl font-bold text-orange-600">{{ metrics.scrub_count }}</p>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-gray-600 text-sm mb-2">Entities Detected</h3>
                <p class="text-4xl font-bold text-blue-600">{{ metrics.entities_detected_total }}</p>
            </div>
            <div class="bg-white rounded-lg shadow p-6">
                <h3 class="text-gray-600 text-sm mb-2">Access Denied</h3>
                <p class="text-4xl font-bold text-red-600">{{ metrics.access_denied_count }}</p>
            </div>
        </div>
        
        <div class="bg-white rounded-lg shadow p-6">
            <h2 class="text-2xl font-bold mb-4">Audit Statistics</h2>
            <div class="space-y-2">
                {% for key, value in stats.items() %}
                <div class="flex justify-between border-b py-2">
                    <span class="text-gray-600">{{ key.replace('_', ' ').title() }}</span>
                    <span class="font-bold">{{ value }}</span>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>
    <script>
        async function logout() {
            await fetch('/api/logout', { method: 'POST' });
            window.location.href = '/login';
        }
    </script>
</body>
</html>
"""

# ============================================================================
# ROUTES
# ============================================================================

@app.route('/')
@login_required
def index():
    """Dashboard."""
    return render_template_string(DASHBOARD_HTML)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if request.method == 'GET':
        return render_template_string(LOGIN_HTML)
    
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    login_user(user)
    return jsonify({'message': 'Login successful'}), 200

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register page."""
    if request.method == 'GET':
        return render_template_string(REGISTER_HTML)
    
    data = request.get_json()
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 409
    
    user = User(username=data['username'], email=data['email'])
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'Registration successful'}), 201

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """Logout."""
    logout_user()
    return jsonify({'message': 'Logged out'}), 200

@app.route('/api/scrub', methods=['POST'])
@login_required
def scrub():
    """Scrub prompt using advanced scrubber."""
    data = request.get_json()
    prompt = data.get('prompt', '')
    
    if not prompt:
        return jsonify({'error': 'No prompt provided'}), 400
    
    try:
        # Use advanced scrubber
        scrubbed_text, entities = scrubber.scrub_text(prompt, user_id=current_user.username)
        
        # Store placeholders for potential de-scrubbing
        descrubber.store_placeholders(entities)
        
        # Calculate confidence
        confidence = sum(e['confidence'] for e in entities) / len(entities) if entities else 1.0
        
        # Save to database
        session_id = hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16]
        scrub_session = ScrubSession(
            session_id=session_id,
            user_id=current_user.id,
            original_prompt=prompt,
            scrubbed_prompt=scrubbed_text,
            entity_count=len(entities),
            confidence_score=confidence,
            entities_json=str(entities)  # Store as JSON string
        )
        
        db.session.add(scrub_session)
        db.session.commit()
        
        return jsonify({
            'session_id': session_id,
            'scrubbed_content': scrubbed_text,
            'entities': entities,
            'entity_count': len(entities),
            'confidence_score': confidence
        }), 200
        
    except Exception as e:
        app.logger.error(f"Scrubbing error: {str(e)}")
        return jsonify({'error': f'Scrubbing failed: {str(e)}'}), 500

@app.route('/history')
@login_required
def history():
    """History page."""
    sessions = ScrubSession.query.filter_by(user_id=current_user.id)\
        .order_by(ScrubSession.created_at.desc())\
        .limit(50).all()
    return render_template_string(HISTORY_HTML, sessions=sessions)

@app.route('/metrics')
@login_required
def metrics():
    """Metrics page."""
    metrics = metrics_observer.get_metrics()
    stats = audit_logger.get_statistics()
    return render_template_string(METRICS_HTML, metrics=metrics, stats=stats)

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db():
    """Initialize database and create default users."""
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin', 
                email='admin@secureprompt.com',
                role='security_admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created (admin / admin123)")
        
        # Create test analyst user
        if not User.query.filter_by(username='analyst').first():
            analyst = User(
                username='analyst',
                email='analyst@secureprompt.com',
                role='data_analyst'
            )
            analyst.set_password('analyst123')
            db.session.add(analyst)
            db.session.commit()
            print("✅ Analyst user created (analyst / analyst123)")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    init_db()
    print("\n" + "="*70)
    print("🚀 SecurePrompt - Combined Advanced Application")
    print("="*70)
    print("📍 URL:       http://localhost:5000")
    print("👤 Admin:     admin / admin123 (security_admin role)")
    print("👤 Analyst:   analyst / analyst123 (data_analyst role)")
    print("\n🔧 Features:")
    print("  ✓ Advanced multi-strategy scrubbing (YAML, Regex, spaCy)")
    print("  ✓ Role-based access control")
    print("  ✓ Complete audit trail")
    print("  ✓ Real-time metrics")
    print("  ✓ ING-branded UI")
    print("="*70 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)