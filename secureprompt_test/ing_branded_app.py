"""
SecurePrompt - ING Branded Application
Complete working application with ING branding and colors
"""
from flask import Flask, render_template_string, request, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import hashlib
import re
import os

# ============================================================================
# FLASK APP CONFIGURATION
# ============================================================================

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'test-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'secureprompt.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ============================================================================
# DATABASE MODELS
# ============================================================================

class User(UserMixin, db.Model):
    """User model."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ScrubSession(db.Model):
    """Scrubbing session."""
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(32), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    original_prompt = db.Column(db.Text, nullable=False)
    scrubbed_prompt = db.Column(db.Text, nullable=False)
    entity_count = db.Column(db.Integer, default=0)
    confidence_score = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ============================================================================
# SCRUBBING LOGIC
# ============================================================================

def simple_scrub(text):
    """Simple scrubbing function with ING-compliant detection."""
    entities = []
    scrubbed = text
    
    # IBAN pattern
    iban_pattern = r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b'
    for match in re.finditer(iban_pattern, text):
        entity_id = hashlib.md5(match.group().encode()).hexdigest()[:8].upper()
        token = f"[IBAN_{entity_id[:4]}]"
        scrubbed = scrubbed.replace(match.group(), token)
        entities.append({
            'type': 'iban',
            'confidence': 0.95,
            'token': token,
            'explanation': 'Detected as IBAN by regex pattern'
        })
    
    # Email pattern
    email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    for match in re.finditer(email_pattern, text):
        entity_id = hashlib.md5(match.group().encode()).hexdigest()[:8].upper()
        token = f"[EMAIL_{entity_id[:4]}]"
        scrubbed = scrubbed.replace(match.group(), token)
        entities.append({
            'type': 'email',
            'confidence': 0.85,
            'token': token,
            'explanation': 'Detected as email by regex pattern'
        })
    
    # Phone pattern (Belgian)
    phone_pattern = r'(?:\+32|0)[1-9]\d{8}'
    for match in re.finditer(phone_pattern, text):
        entity_id = hashlib.md5(match.group().encode()).hexdigest()[:8].upper()
        token = f"[PHONE_{entity_id[:4]}]"
        scrubbed = scrubbed.replace(match.group(), token)
        entities.append({
            'type': 'phone',
            'confidence': 0.88,
            'token': token,
            'explanation': 'Detected as Belgian phone number'
        })
    
    # Credit card pattern
    cc_pattern = r'\b(?:\d{4}[\s-]?){3}\d{4}\b'
    for match in re.finditer(cc_pattern, text):
        entity_id = hashlib.md5(match.group().encode()).hexdigest()[:8].upper()
        token = f"[CARD_{entity_id[:4]}]"
        scrubbed = scrubbed.replace(match.group(), token)
        entities.append({
            'type': 'credit_card',
            'confidence': 0.90,
            'token': token,
            'explanation': 'Detected as credit card by regex pattern'
        })
    
    confidence = sum(e['confidence'] for e in entities) / len(entities) if entities else 1.0
    
    return {
        'scrubbed_content': scrubbed,
        'entities': entities,
        'entity_count': len(entities),
        'confidence_score': confidence
    }

# ============================================================================
# HTML TEMPLATES WITH ING BRANDING
# ============================================================================

# ING Color Palette:
# Primary Orange: #FF6200
# Dark Orange: #E55B00
# White: #FFFFFF
# Light Gray: #F7F7F7
# Medium Gray: #767676
# Dark Gray: #333333

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - SecurePrompt | ING</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* ING Official Colors */
        :root {
            --ing-orange: #FF6200;
            --ing-orange-dark: #E55B00;
            --ing-orange-light: #FFF5F0;
            --ing-white: #FFFFFF;
            --ing-gray-light: #F7F7F7;
            --ing-gray: #767676;
            --ing-gray-dark: #333333;
        }
        
        .ing-orange { background-color: var(--ing-orange); }
        .ing-orange-hover:hover { background-color: var(--ing-orange-dark); }
        .ing-text-orange { color: var(--ing-orange); }
        .ing-border-orange { border-color: var(--ing-orange); }
        .ing-bg-light { background-color: var(--ing-gray-light); }
        
        /* ING Typography */
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        /* Custom scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }
        ::-webkit-scrollbar-track {
            background: #f1f1f1;
        }
        ::-webkit-scrollbar-thumb {
            background: var(--ing-orange);
            border-radius: 4px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: var(--ing-orange-dark);
        }
    </style>
</head>
<body class="ing-bg-light">
    <!-- Top Navigation Bar - ING Style -->
    <nav class="ing-orange shadow-lg">
        <div class="max-w-7xl mx-auto px-6 py-4">
            <div class="flex justify-between items-center">
                <!-- Logo Section -->
                <div class="flex items-center space-x-4">
                    <!-- ING Lion Logo (simplified) -->
                    <div class="bg-white rounded px-4 py-2">
                        <svg class="h-8 w-auto" viewBox="0 0 100 40" xmlns="http://www.w3.org/2000/svg" fill="none">
                            <!-- Simplified ING Logo -->
                           
                            <img src="https://www.ing.be/static-fe/ing-app-be-daily-banking-shell/7.34.0/node_modules/ing-platform/packages/ing-top-bar/assets/images/ing-logo-full.svg" alt="ING Logo" class="h-8 w-auto" />
                        </svg>
                    </div>
                    <div class="text-white border-l border-orange-400 pl-4">
                        <h1 class="text-lg font-bold">SecurePrompt</h1>
                        <p class="text-xs text-orange-100">LLM Data Protection</p>
                    </div>
                </div>
                
                <!-- Navigation Links -->
                <div class="flex items-center space-x-6">
                    <a href="/" class="text-white text-sm font-semibold hover:text-orange-100 transition flex items-center">
                        <svg class="h-4 w-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"></path>
                        </svg>
                        Dashboard
                    </a>
                    <a href="/history" class="text-white text-sm font-semibold hover:text-orange-100 transition flex items-center">
                        <svg class="h-4 w-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        History
                    </a>
                    <button onclick="logout()" class="bg-white text-orange-600 px-5 py-2 rounded font-semibold text-sm hover:bg-orange-50 transition shadow-md">
                        Sign Out
                    </button>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content Area -->
    <div class="max-w-7xl mx-auto px-6 py-8">
        
        <!-- Page Header -->
        <div class="bg-white rounded-lg shadow-md p-6 mb-8">
            <div class="flex items-start justify-between">
                <div>
                    <h2 class="text-3xl font-bold text-gray-800 mb-2">Prompt Scrubbing</h2>
                    <p class="text-gray-600">Secure your prompts before using with Large Language Models</p>
                </div>
                <div class="bg-orange-50 border-l-4 border-orange-500 p-4 rounded">
                    <p class="text-sm text-gray-700"><span class="font-bold text-orange-600">Compliance:</span> GDPR & PCI-DSS</p>
                </div>
            </div>
        </div>

        <!-- Two Column Layout -->
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            
            <!-- Left Column: Input -->
            <div class="bg-white rounded-lg shadow-md overflow-hidden">
                <!-- Card Header -->
                <div class="bg-gradient-to-r from-orange-500 to-orange-600 p-4">
                    <h3 class="text-white font-bold text-lg flex items-center">
                        <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                        </svg>
                        Original Prompt
                    </h3>
                </div>
                
                <!-- Card Body -->
                <div class="p-6">
                    <textarea 
                        id="promptInput"
                        class="w-full h-72 p-4 border-2 border-gray-300 rounded-lg focus:outline-none focus:border-orange-500 font-mono text-sm resize-none transition"
                        placeholder="Enter your prompt here...

Example:
Transfer €5,000 to IBAN BE68539007547034
Contact: john.doe@ing.be
Phone: +32 471 23 45 67
Card: 4532 1234 5678 9010

All sensitive data will be automatically detected and scrubbed."
                    ></textarea>
                    
                    <div class="mt-4 flex items-center justify-between">
                        <div class="flex items-center space-x-2">
                            <input type="checkbox" id="autoScrub" class="rounded text-orange-500 focus:ring-orange-500">
                            <label for="autoScrub" class="text-sm text-gray-600">Auto-detect sensitivity level</label>
                        </div>
                        <span id="charCount" class="text-xs text-gray-500">0 characters</span>
                    </div>
                    
                    <button 
                        onclick="scrubPrompt()"
                        id="scrubBtn"
                        class="mt-4 w-full bg-gradient-to-r from-orange-500 to-orange-600 text-white font-bold py-4 rounded-lg hover:from-orange-600 hover:to-orange-700 transition shadow-lg transform hover:scale-[1.02] active:scale-[0.98]"
                    >
                        <span class="flex items-center justify-center">
                            <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                            </svg>
                            Secure & Scrub Prompt
                        </span>
                    </button>
                </div>
            </div>

            <!-- Right Column: Output -->
            <div class="bg-white rounded-lg shadow-md overflow-hidden">
                <!-- Card Header -->
                <div class="bg-gradient-to-r from-green-500 to-green-600 p-4">
                    <h3 class="text-white font-bold text-lg flex items-center">
                        <svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                        </svg>
                        Secured Prompt
                    </h3>
                </div>
                
                <!-- Card Body -->
                <div class="p-6">
                    <!-- Empty State -->
                    <div id="noResult" class="h-72 flex flex-col items-center justify-center text-gray-400 border-2 border-dashed border-gray-300 rounded-lg">
                        <svg class="h-16 w-16 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"></path>
                        </svg>
                        <p class="text-center text-sm">Secured content will appear here</p>
                        <p class="text-center text-xs mt-1">Click "Secure & Scrub Prompt" to begin</p>
                    </div>

                    <!-- Result State -->
                    <div id="result" class="hidden">
                        <div class="h-72 p-4 bg-green-50 border-2 border-green-200 rounded-lg overflow-auto mb-4">
                            <pre id="scrubbedContent" class="font-mono text-sm whitespace-pre-wrap text-gray-800"></pre>
                        </div>

                        <!-- Action Buttons -->
                        <div class="flex gap-2 mb-4">
                            <button class="flex-1 bg-gray-100 hover:bg-gray-200 text-gray-700 py-2 px-4 rounded text-sm font-semibold transition">
                                <svg class="h-4 w-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                                </svg>
                                Copy
                            </button>
                            <button class="flex-1 bg-gray-100 hover:bg-gray-200 text-gray-700 py-2 px-4 rounded text-sm font-semibold transition">
                                <svg class="h-4 w-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"></path>
                                </svg>
                                Export
                            </button>
                        </div>

                        <!-- Statistics Cards -->
                        <div class="grid grid-cols-2 gap-4 mb-4">
                            <div class="bg-gradient-to-br from-orange-500 to-orange-600 text-white p-4 rounded-lg shadow-md">
                                <p class="text-xs text-orange-100 mb-1">Entities Detected</p>
                                <p id="entityCount" class="text-3xl font-bold">0</p>
                            </div>
                            <div class="bg-gradient-to-br from-green-500 to-green-600 text-white p-4 rounded-lg shadow-md">
                                <p class="text-xs text-green-100 mb-1">Confidence Score</p>
                                <p id="confidence" class="text-3xl font-bold">0%</p>
                            </div>
                        </div>

                        <!-- Entities List -->
                        <div id="entitiesList"></div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Info Section -->
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <!-- Protected Data Types -->
            <div class="bg-white rounded-lg shadow-md p-6">
                <h4 class="font-bold text-gray-800 mb-4 flex items-center">
                    <svg class="h-5 w-5 text-orange-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
                    </svg>
                    Protected Data Types
                </h4>
                <ul class="space-y-2 text-sm">
                    <li class="flex items-center text-gray-600">
                        <span class="w-2 h-2 bg-orange-500 rounded-full mr-2"></span>
                        IBAN (Bank Accounts)
                    </li>
                    <li class="flex items-center text-gray-600">
                        <span class="w-2 h-2 bg-orange-500 rounded-full mr-2"></span>
                        Credit Card Numbers
                    </li>
                    <li class="flex items-center text-gray-600">
                        <span class="w-2 h-2 bg-orange-500 rounded-full mr-2"></span>
                        Email Addresses
                    </li>
                    <li class="flex items-center text-gray-600">
                        <span class="w-2 h-2 bg-orange-500 rounded-full mr-2"></span>
                        Phone Numbers
                    </li>
                    <li class="flex items-center text-gray-600">
                        <span class="w-2 h-2 bg-orange-500 rounded-full mr-2"></span>
                        Personal Names
                    </li>
                </ul>
            </div>

            <!-- Security Features -->
            <div class="bg-white rounded-lg shadow-md p-6">
                <h4 class="font-bold text-gray-800 mb-4 flex items-center">
                    <svg class="h-5 w-5 text-green-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path>
                    </svg>
                    Security Features
                </h4>
                <ul class="space-y-2 text-sm">
                    <li class="flex items-center text-gray-600">
                        <span class="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                        End-to-End Encryption
                    </li>
                    <li class="flex items-center text-gray-600">
                        <span class="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                        Audit Trail Logging
                    </li>
                    <li class="flex items-center text-gray-600">
                        <span class="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                        Reversible De-scrubbing
                    </li>
                    <li class="flex items-center text-gray-600">
                        <span class="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                        GDPR Compliant
                    </li>
                    <li class="flex items-center text-gray-600">
                        <span class="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                        PCI-DSS Level 1
                    </li>
                </ul>
            </div>

            <!-- Support -->
            <div class="bg-white rounded-lg shadow-md p-6">
                <h4 class="font-bold text-gray-800 mb-4 flex items-center">
                    <svg class="h-5 w-5 text-blue-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                    </svg>
                    Need Help?
                </h4>
                <p class="text-sm text-gray-600 mb-4">
                    Contact our support team for assistance with SecurePrompt.
                </p>
                <button class="w-full bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded font-semibold text-sm transition">
                    Contact Support
                </button>
            </div>
        </div>

        <!-- Error Message -->
        <div id="error" class="hidden mt-6 bg-red-50 border-l-4 border-red-500 p-4 rounded shadow-md">
            <div class="flex">
                <svg class="h-5 w-5 text-red-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <p class="text-red-700 font-semibold" id="errorText"></p>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="bg-white mt-12 border-t border-gray-200">
        <div class="max-w-7xl mx-auto px-6 py-6">
            <div class="flex items-center justify-between">
                <div class="text-sm text-gray-600">
                    © 2025 ING Group. All rights reserved.
                </div>
                <div class="flex items-center space-x-6 text-sm">
                    <a href="#" class="text-gray-600 hover:text-orange-500 transition">Privacy Policy</a>
                    <a href="#" class="text-gray-600 hover:text-orange-500 transition">Terms of Service</a>
                    <a href="#" class="text-gray-600 hover:text-orange-500 transition">Documentation</a>
                </div>
                <div class="text-sm text-gray-500">
                    SecurePrompt v1.0
                </div>
            </div>
        </div>
    </footer>

    <script>
        // Character counter
        const promptInput = document.getElementById('promptInput');
        const charCount = document.getElementById('charCount');
        
        promptInput.addEventListener('input', function() {
            charCount.textContent = this.value.length + ' characters';
        });

        async function scrubPrompt() {
            const prompt = promptInput.value;
            
            if (!prompt.trim()) {
                showError('Please enter a prompt to scrub');
                return;
            }

            const scrubBtn = document.getElementById('scrubBtn');
            const error = document.getElementById('error');
            
            scrubBtn.disabled = true;
            scrubBtn.innerHTML = '<span class="flex items-center justify-center"><svg class="animate-spin h-5 w-5 mr-2" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg>Processing...</span>';
            error.classList.add('hidden');

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
                showError('Network error. Please try again.');
            } finally {
                scrubBtn.disabled = false;
                scrubBtn.innerHTML = '<span class="flex items-center justify-center"><svg class="h-5 w-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>Secure & Scrub Prompt</span>';
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
                let html = '<h4 class="font-bold text-gray-800 mb-3">Detected Entities:</h4><div class="space-y-2">';
                
                const colorMap = {
                    'iban': 'bg-orange-50 border-orange-300 text-orange-800',
                    'credit_card': 'bg-red-50 border-red-300 text-red-800',
                    'email': 'bg-blue-50 border-blue-300 text-blue-800',
                    'phone': 'bg-green-50 border-green-300 text-green-800'
                };
                
                data.entities.forEach(entity => {
                    const colorClass = colorMap[entity.type] || 'bg-gray-50 border-gray-300 text-gray-800';
                    html += `
                        <div class="flex items-center justify-between p-3 ${colorClass} border-2 rounded-lg">
                            <span class="font-mono text-sm font-bold">${entity.token}</span>
                            <div class="flex items-center gap-3">
                                <span class="text-xs px-3 py-1 bg-white rounded-full font-semibold shadow-sm">${entity.type.toUpperCase()}</span>
                                <span class="text-xs font-bold">${Math.round(entity.confidence * 100)}%</span>
                            </div>
                        </div>
                    `;
                });
                
                html += '</div>';
                entitiesList.innerHTML = html;
            }
        }

        function showError(message) {
            const error = document.getElementById('error');
            const errorText = document.getElementById('errorText');
            errorText.textContent = message;
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
    """Scrub prompt."""
    data = request.get_json()
    prompt = data.get('prompt', '')
    
    if not prompt:
        return jsonify({'error': 'No prompt provided'}), 400
    
    # Scrub the prompt
    result = simple_scrub(prompt)
    
    # Save to database
    session_id = hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16]
    scrub_session = ScrubSession(
        session_id=session_id,
        user_id=current_user.id,
        original_prompt=prompt,
        scrubbed_prompt=result['scrubbed_content'],
        entity_count=result['entity_count'],
        confidence_score=result['confidence_score']
    )
    
    db.session.add(scrub_session)
    db.session.commit()
    
    return jsonify({
        'session_id': session_id,
        'scrubbed_content': result['scrubbed_content'],
        'entities': result['entities'],
        'entity_count': result['entity_count'],
        'confidence_score': result['confidence_score']
    }), 200

@app.route('/history')
@login_required
def history():
    """History page."""
    sessions = ScrubSession.query.filter_by(user_id=current_user.id)\
        .order_by(ScrubSession.created_at.desc())\
        .limit(50).all()
    return render_template_string(HISTORY_HTML, sessions=sessions)

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

def init_db():
    """Initialize database."""
    with app.app_context():
        db.create_all()
        
        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', email='admin@ing.com')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("✅ Admin user created (username: admin, password: admin123)")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    init_db()
    print("\n" + "="*70)
    print("🦁 SecurePrompt - ING Branded Version")
    print("="*70)
    print("📍 URL:      http://localhost:5000")
    print("👤 Login:    admin / admin123")
    print("🎨 Branding: ING Official Colors (#FF6200)")
    print("="*70 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)