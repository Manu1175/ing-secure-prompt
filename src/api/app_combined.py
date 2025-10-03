# src/api/app_combined.py
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, Request, Response, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

# --- Import your Scrubber ---
# Make sure src/api/scrubber.py contains the class provided earlier
try:
    from scrubber import Scrubber
except Exception:
    # allow running as "python src/api/app_combined.py"
    import sys
    sys.path.append(str(Path(__file__).resolve().parent))
    from scrubber import Scrubber


# --------------------------
# Locate config (rules.yaml)
# --------------------------
HERE = Path(__file__).resolve().parent
# Try project root two levels up (.. / ..)
CANDIDATES = [
    HERE.parents[2] / "config",
    HERE.parents[1] / "config",
    HERE / "config",
]
CONFIG_DIR: Optional[Path] = next((p for p in CANDIDATES if p.exists()), None)
if not CONFIG_DIR:
    # create a local config with minimal defaults if missing
    CONFIG_DIR = HERE / "config"
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    (CONFIG_DIR / "rules.yaml").write_text(
        'rules:\n'
        '  - column: Email\n'
        '    detection:\n'
        '      type: regex\n'
        '      pattern: "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"\n'
        '    placeholder: "{{EMAIL}}"\n'
        '    recommended_classification: CONFIDENTIAL\n'
        '    priority: 1\n'
        '    confidence: 1.0\n'
        '  - column: Phone Number\n'
        '    detection:\n'
        '      type: regex\n'
        '      pattern: "(?:\\+?\\d{1,3})?[-.\\s]?\\(?\\d{1,4}\\)?[-.\\s]?\\d{3,4}[-.\\s]?\\d{3,4}"\n'
        '    placeholder: "{{PHONE}}"\n'
        '    recommended_classification: CONFIDENTIAL\n'
        '    priority: 1\n'
        '    confidence: 1.0\n',
        encoding="utf-8"
    )
    (CONFIG_DIR / "whitelist.yaml").write_text(
        '- type: domain_term\n'
        '  text: "ING"\n',
        encoding="utf-8"
    )

RULES_PATH = str((CONFIG_DIR / "rules.yaml").resolve())
WHITELIST_PATH = str((CONFIG_DIR / "whitelist.yaml").resolve())

scrubber = Scrubber(rules_yaml=RULES_PATH, whitelist_yaml=WHITELIST_PATH)

# --------------------------
# Minimal in-memory storage
# --------------------------
USERS: Dict[str, Dict] = {
    "admin": {"username": "admin", "email": "admin@demo.local", "password": "admin123"}
}
SESSIONS: Dict[str, Dict] = {}  # key = username, value = last scrub result list, timestamps
HISTORY: List[Dict] = []        # list of {username, scrubbed_prompt, entity_count, confidence_score, created_at}

def require_user(request: Request) -> Optional[str]:
    return request.cookies.get("sp_user")

# --------------------------
# HTML templates (ING style)
# --------------------------
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Login - SecurePrompt | ING</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --ing-orange: #FF6200; --ing-orange-dark: #E55B00;
      --ing-gray-light:#F7F7F7; --ing-gray:#767676; --ing-gray-dark:#333;
    }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
  </style>
</head>
<body class="bg-gradient-to-br from-blue-500 to-purple-600 min-h-screen flex items-center justify-center">
  <div class="bg-white rounded-lg shadow-2xl p-8 w-full max-w-md">
    <div class="text-center mb-8">
      <div class="flex items-center justify-center mb-3">
        <img src="https://www.ing.be/static-fe/ing-app-be-daily-banking-shell/7.34.0/node_modules/ing-platform/packages/ing-top-bar/assets/images/ing-logo-full.svg" alt="ING Logo" class="h-8"/>
      </div>
      <h1 class="text-3xl font-bold text-gray-800">🔒 SecurePrompt</h1>
      <p class="text-gray-600 mt-1">Banking LLM Security System</p>
    </div>

    <form id="loginForm" onsubmit="handleLogin(event)">
      <label class="block text-gray-700 font-semibold mb-2">Username</label>
      <input id="username" value="admin" class="w-full px-4 py-2 border rounded-lg mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500" required/>
      <label class="block text-gray-700 font-semibold mb-2">Password</label>
      <input id="password" type="password" value="admin123" class="w-full px-4 py-2 border rounded-lg mb-4 focus:outline-none focus:ring-2 focus:ring-blue-500" required/>
      <div id="errorMsg" class="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded hidden"><p id="errorText"></p></div>
      <button id="loginBtn" class="w-full bg-blue-600 text-white font-semibold py-3 rounded-lg hover:bg-blue-700 transition">Login</button>
    </form>

    <p class="text-center mt-6 text-gray-600">
      Don't have an account?
      <a href="/register" class="text-blue-600 hover:underline font-semibold">Register</a>
    </p>
  </div>

  <script>
    async function handleLogin(e){
      e.preventDefault();
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const btn = document.getElementById('loginBtn');
      const box = document.getElementById('errorMsg'); const txt = document.getElementById('errorText');
      btn.disabled = true; btn.textContent = 'Logging in...'; box.classList.add('hidden');
      try{
        const r = await fetch('/login', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username, password})});
        if(r.ok){ window.location.href = '/'; }
        else{ const d=await r.json(); txt.textContent = d.error || 'Login failed'; box.classList.remove('hidden'); }
      }catch(_){ txt.textContent='Network error'; box.classList.remove('hidden'); }
      finally{ btn.disabled=false; btn.textContent='Login'; }
    }
  </script>
</body>
</html>
"""

REGISTER_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Register - SecurePrompt | ING</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root { --ing-orange:#FF6200; --ing-orange-dark:#E55B00; }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
  </style>
</head>
<body class="bg-gradient-to-br from-blue-500 to-purple-600 min-h-screen flex items-center justify-center">
  <div class="bg-white rounded-lg shadow-2xl p-8 w-full max-w-md">
    <div class="text-center mb-8">
      <img src="https://www.ing.be/static-fe/ing-app-be-daily-banking-shell/7.34.0/node_modules/ing-platform/packages/ing-top-bar/assets/images/ing-logo-full.svg" class="h-8 mx-auto mb-3" />
      <h1 class="text-3xl font-bold text-gray-800">Create your account</h1>
    </div>
    <form id="registerForm" onsubmit="handleRegister(event)">
      <label class="block text-gray-700 font-semibold mb-2">Username</label>
      <input id="username" class="w-full px-4 py-2 border rounded-lg mb-4" required />
      <label class="block text-gray-700 font-semibold mb-2">Email</label>
      <input id="email" type="email" class="w-full px-4 py-2 border rounded-lg mb-4" required />
      <label class="block text-gray-700 font-semibold mb-2">Password</label>
      <input id="password" type="password" class="w-full px-4 py-2 border rounded-lg mb-4" required />
      <div id="errorMsg" class="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded hidden"><p id="errorText"></p></div>
      <div id="successMsg" class="mb-4 p-3 bg-green-100 border border-green-400 text-green-700 rounded hidden"><p id="successText"></p></div>
      <button id="registerBtn" class="w-full bg-blue-600 text-white font-semibold py-3 rounded-lg hover:bg-blue-700 transition">Register</button>
    </form>
    <p class="text-center mt-6 text-gray-600">Already have an account? <a class="text-blue-600 hover:underline font-semibold" href="/login">Login</a></p>
  </div>
  <script>
    async function handleRegister(e){
      e.preventDefault();
      const username = document.getElementById('username').value;
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;
      const btn = document.getElementById('registerBtn');
      const err = document.getElementById('errorMsg'); const et = document.getElementById('errorText');
      const ok = document.getElementById('successMsg'); const st = document.getElementById('successText');
      btn.disabled=true; btn.textContent='Creating account...'; err.classList.add('hidden'); ok.classList.add('hidden');
      try{
        const r = await fetch('/register',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username,email,password})});
        if(r.ok){ st.textContent='Registration successful! Redirecting to login...'; ok.classList.remove('hidden'); setTimeout(()=>window.location.href='/login',1500); }
        else{ const d=await r.json(); et.textContent=d.error||'Registration failed'; err.classList.remove('hidden'); }
      }catch(_){ et.textContent='Network error'; err.classList.remove('hidden'); }
      finally{ btn.disabled=false; btn.textContent='Register'; }
    }
  </script>
</body>
</html>
"""

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Dashboard - SecurePrompt | ING</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --ing-orange:#FF6200; --ing-orange-dark:#E55B00;
      --ing-gray-light:#F7F7F7; --ing-gray:#767676; --ing-gray-dark:#333333;
    }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
  </style>
</head>
<body class="bg-gray-50">
  <nav class="bg-[color:var(--ing-orange)] shadow-lg">
    <div class="max-w-7xl mx-auto px-6 py-4">
      <div class="flex justify-between items-center">
        <div class="flex items-center space-x-4">
          <div class="bg-white rounded px-4 py-2">
            <img src="https://www.ing.be/static-fe/ing-app-be-daily-banking-shell/7.34.0/node_modules/ing-platform/packages/ing-top-bar/assets/images/ing-logo-full.svg" class="h-8" />
          </div>
          <div class="text-white border-l border-orange-300 pl-4">
            <h1 class="text-lg font-bold">SecurePrompt</h1>
            <p class="text-xs text-orange-100">LLM Data Protection</p>
          </div>
        </div>
        <div class="flex items-center space-x-6">
          <a href="/" class="text-white text-sm font-semibold hover:text-orange-100">Dashboard</a>
          <a href="/history" class="text-white text-sm font-semibold hover:text-orange-100">History</a>
          <a href="/metrics" class="text-white text-sm font-semibold hover:text-orange-100">Metrics</a>
          <button onclick="logout()" class="bg-white text-orange-600 px-5 py-2 rounded font-semibold text-sm hover:bg-orange-50 transition shadow-md">Sign Out</button>
        </div>
      </div>
    </div>
  </nav>

  <div class="max-w-7xl mx-auto px-6 py-8">
    <div class="bg-white rounded-lg shadow-md p-6 mb-8">
      <div class="flex items-start justify-between">
        <div>
          <h2 class="text-3xl font-bold text-gray-800 mb-2">Prompt Scrubbing</h2>
          <p class="text-gray-600">Secure your prompts before sending them to Large Language Models.</p>
        </div>
        <div class="bg-orange-50 border-l-4 border-orange-500 p-4 rounded">
          <p class="text-sm text-gray-700"><span class="font-bold text-orange-600">Compliance:</span> GDPR & PCI-DSS</p>
        </div>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
      <!-- Input -->
      <div class="bg-white rounded-lg shadow-md overflow-hidden">
        <div class="bg-gradient-to-r from-orange-500 to-orange-600 p-4">
          <h3 class="text-white font-bold text-lg">Original Prompt</h3>
        </div>
        <div class="p-6">
          <textarea id="promptInput" class="w-full h-72 p-4 border-2 border-gray-300 rounded-lg focus:outline-none focus:border-orange-500 font-mono text-sm resize-none transition"
placeholder="Enter your prompt here...

Example:
Transfer €5,000 to IBAN BE68539007547034
Contact: john.doe@ing.be
Phone: +32 471 23 45 67
Card: 4532 1234 5678 9010

All sensitive data will be automatically detected and scrubbed."></textarea>
          <div class="mt-4 flex items-center justify-between">
            <div class="flex items-center space-x-2">
              <input type="checkbox" id="autoScrub" class="rounded text-orange-500 focus:ring-orange-500">
              <label for="autoScrub" class="text-sm text-gray-600">Auto-detect sensitivity level</label>
            </div>
            <span id="charCount" class="text-xs text-gray-500">0 characters</span>
          </div>
          <button onclick="scrubPrompt()" id="scrubBtn" class="mt-4 w-full bg-gradient-to-r from-orange-500 to-orange-600 text-white font-bold py-4 rounded-lg hover:from-orange-600 hover:to-orange-700 transition shadow-lg">Secure & Scrub</button>
        </div>
      </div>

      <!-- Output -->
      <div class="bg-white rounded-lg shadow-md overflow-hidden">
        <div class="bg-[#000066] p-4">
          <h3 class="text-white font-bold text-lg">Secured Prompt</h3>
        </div>
        <div class="p-6">
          <div id="noResult" class="h-72 flex flex-col items-center justify-center text-gray-400 border-2 border-dashed border-gray-300 rounded-lg">
            <p class="text-center text-sm">Secured content will appear here</p>
            <p class="text-center text-xs mt-1">Click "Secure & Scrub" to begin</p>
          </div>
          <div id="result" class="hidden">
            <div class="h-72 p-4 bg-green-50 border-2 border-green-200 rounded-lg overflow-auto mb-4">
              <pre id="scrubbedContent" class="font-mono text-sm whitespace-pre-wrap text-gray-800"></pre>
            </div>
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
            <div id="entitiesList"></div>
          </div>
        </div>
      </div>
    </div>

    <div id="error" class="hidden mt-6 bg-red-50 border-l-4 border-red-500 p-4 rounded shadow-md">
      <p class="text-red-700 font-semibold" id="errorText"></p>
    </div>
  </div>

  <footer class="bg-white mt-12 border-t border-gray-200">
    <div class="max-w-7xl mx-auto px-6 py-6 flex items-center justify-between text-sm text-gray-600">
      <span>© 2025 ING Group. All rights reserved.</span>
      <div class="flex items-center space-x-6">
        <a href="#" class="hover:text-orange-500">Privacy Policy</a>
        <a href="#" class="hover:text-orange-500">Terms of Service</a>
        <a href="#" class="hover:text-orange-500">Documentation</a>
      </div>
      <span>SecurePrompt v1.0</span>
    </div>
  </footer>

  <script>
    const promptInput = document.getElementById('promptInput');
    const charCount = document.getElementById('charCount');
    promptInput.addEventListener('input', () => { charCount.textContent = promptInput.value.length + ' characters'; });

    async function scrubPrompt(){
      const prompt = promptInput.value;
      if(!prompt.trim()){ showError('Please enter a prompt to scrub'); return; }
      const btn = document.getElementById('scrubBtn');
      const err = document.getElementById('error'); const et = document.getElementById('errorText');
      btn.disabled = true; btn.textContent='Processing...'; err.classList.add('hidden');
      try{
        const r = await fetch('/api/scrub', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({prompt})});
        if(r.ok){ const d = await r.json(); displayResult(d); }
        else{ const d = await r.json(); showError(d.error || 'Scrubbing failed'); }
      }catch(_){ showError('Network error'); }
      finally{ btn.disabled=false; btn.textContent='Secure & Scrub'; }
    }

    function displayResult(d){
      document.getElementById('noResult').classList.add('hidden');
      document.getElementById('result').classList.remove('hidden');
      document.getElementById('scrubbedContent').textContent = d.scrubbed_content;
      document.getElementById('entityCount').textContent = d.entity_count;
      document.getElementById('confidence').textContent = Math.round(d.confidence_score * 100) + '%';

      const entitiesList = document.getElementById('entitiesList');
      if(d.entities && d.entities.length){
        let html = '<h4 class="font-bold text-gray-800 mb-3">Detected Entities:</h4><div class="space-y-2">';
        const colorMap = { 'iban':'bg-orange-50 border-orange-300 text-orange-800', 'credit_card':'bg-red-50 border-red-300 text-red-800', 'Email':'bg-blue-50 border-blue-300 text-blue-800', 'Phone Number':'bg-green-50 border-green-300 text-green-800' };
        d.entities.forEach(e=>{
          const label = e.entity || e.type || 'ENTITY';
          const token = e.id || e.token || 'N/A';
          const conf = Math.round((e.confidence || 0.9) * 100);
          const cc = colorMap[label] || 'bg-gray-50 border-gray-300 text-gray-800';
          html += `<div class="flex items-center justify-between p-3 ${cc} border-2 rounded-lg">
            <span class="font-mono text-sm font-bold">${token}</span>
            <div class="flex items-center gap-3">
              <span class="text-xs px-3 py-1 bg-white rounded-full font-semibold shadow-sm">${label.toUpperCase()}</span>
              <span class="text-xs font-bold">${conf}%</span>
            </div></div>`;
        });
        html += '</div>';
        entitiesList.innerHTML = html;
      }
    }

    function showError(msg){
      const e = document.getElementById('error'); const t = document.getElementById('errorText');
      t.textContent = msg; e.classList.remove('hidden'); setTimeout(()=>e.classList.add('hidden'), 4000);
    }

    async function logout(){
      const r = await fetch('/api/logout', {method:'POST'});
      if(r.ok) window.location.href = '/login';
    }
  </script>
</body>
</html>
"""

HISTORY_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Dashboard - SecurePrompt | ING</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --ing-orange:#FF6200; --ing-orange-dark:#E55B00;
      --ing-gray-light:#F7F7F7; --ing-gray:#767676; --ing-gray-dark:#333333;
    }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
  </style>
</head>
<body class="bg-gray-50">
   <nav class="bg-[color:var(--ing-orange)] shadow-lg">
    <div class="max-w-7xl mx-auto px-6 py-4">
      <div class="flex justify-between items-center">
        <div class="flex items-center space-x-4">
          <div class="bg-white rounded px-4 py-2">
            <img src="https://www.ing.be/static-fe/ing-app-be-daily-banking-shell/7.34.0/node_modules/ing-platform/packages/ing-top-bar/assets/images/ing-logo-full.svg" class="h-8" />
          </div>
          <div class="text-white border-l border-orange-300 pl-4">
            <h1 class="text-lg font-bold">SecurePrompt</h1>
            <p class="text-xs text-orange-100">LLM Data Protection</p>
          </div>
        </div>
        <div class="flex items-center space-x-6">
          <a href="/" class="text-white text-sm font-semibold hover:text-orange-100">Dashboard</a>
          <a href="/history" class="text-white text-sm font-semibold hover:text-orange-100">History</a>
          <a href="/metrics" class="text-white text-sm font-semibold hover:text-orange-100">Metrics</a>
          <button onclick="logout()" class="bg-white text-orange-600 px-5 py-2 rounded font-semibold text-sm hover:bg-orange-50 transition shadow-md">Sign Out</button>
        </div>
      </div>
    </div>
  </nav>

  <div class="max-w-7xl mx-auto py-8 px-4">
    <div class="bg-white rounded-lg shadow p-6">
      <h2 class="text-2xl font-bold mb-6">Scrubbing History</h2>
      {% if sessions %}
      <div class="space-y-4">
        {% for s in sessions %}
        <div class="border rounded-lg p-4 hover:bg-gray-50">
          <p class="font-mono text-sm text-gray-600 mb-2">{{ s['created_at'] }}</p>
          <p class="text-gray-800 mb-2">{{ s['scrubbed_prompt'][:200] }}{% if s['scrubbed_prompt']|length > 200 %}...{% endif %}</p>
          <div class="flex gap-4 text-sm">
            <span class="text-blue-600">{{ s['entity_count'] }} entities</span>
            <span class="text-green-600">{{ int(s['confidence_score']*100) }}% confidence</span>
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
    async function logout(){ await fetch('/api/logout', {method:'POST'}); window.location.href='/login'; }
  </script>
</body>
</html>
"""
METRICS_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Dashboard - SecurePrompt | ING</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    :root {
      --ing-orange:#FF6200; --ing-orange-dark:#E55B00;
      --ing-gray-light:#F7F7F7; --ing-gray:#767676; --ing-gray-dark:#333333;
    }
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
  </style>
</head>
<body class="bg-gray-50">
     <nav class="bg-[color:var(--ing-orange)] shadow-lg">
    <div class="max-w-7xl mx-auto px-6 py-4">
      <div class="flex justify-between items-center">
        <div class="flex items-center space-x-4">
          <div class="bg-white rounded px-4 py-2">
            <img src="https://www.ing.be/static-fe/ing-app-be-daily-banking-shell/7.34.0/node_modules/ing-platform/packages/ing-top-bar/assets/images/ing-logo-full.svg" class="h-8" />
          </div>
          <div class="text-white border-l border-orange-300 pl-4">
            <h1 class="text-lg font-bold">SecurePrompt</h1>
            <p class="text-xs text-orange-100">LLM Data Protection</p>
          </div>
        </div>
        <div class="flex items-center space-x-6">
          <a href="/" class="text-white text-sm font-semibold hover:text-orange-100">Dashboard</a>
          <a href="/history" class="text-white text-sm font-semibold hover:text-orange-100">History</a>
          <a href="/metrics" class="text-white text-sm font-semibold hover:text-orange-100">Metrics</a>
          <button onclick="logout()" class="bg-white text-orange-600 px-5 py-2 rounded font-semibold text-sm hover:bg-orange-50 transition shadow-md">Sign Out</button>
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

# --------------------------
# FastAPI app & routes
# --------------------------
app = FastAPI(title="SecurePrompt | ING", version="1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

def _html(template: str, **ctx) -> HTMLResponse:
    # ultra-lightweight {{ }} replacement for demo Jinja-like blocks in HISTORY
    out = template
    if "sessions" in ctx:
        sessions = ctx["sessions"]
        if sessions:
            # crude, render loop:
            block = ""
            for s in sessions:
                block += (
                    '<div class="border rounded-lg p-4 hover:bg-gray-50">'
                    f'<p class="font-mono text-sm text-gray-600 mb-2">{s["created_at"]}</p>'
                    f'<p class="text-gray-800 mb-2">{(s["scrubbed_prompt"][:200] + ("..." if len(s["scrubbed_prompt"])>200 else ""))}</p>'
                    f'<div class="flex gap-4 text-sm">'
                    f'<span class="text-blue-600">{s["entity_count"]} entities</span>'
                    f'<span class="text-green-600">{int(s["confidence_score"]*100)}% confidence</span>'
                    f'</div></div>'
                )
            out = out.replace("{% if sessions %}", "").replace("{% else %}", "").replace("{% endif %}", "")
            out = out.replace("{% for s in sessions %}", "").replace("{% endfor %}", "")
            # inject rendered blocks (replace a placeholder segment)
            # naive: place after the title container by replacing the whole block
            # We'll just drop the loop markers entirely and append block
            out = out.replace("</div>\n  </div>\n\n  <script>", f"{block}</div>\n  </div>\n\n  <script>")
        else:
            # replace blocks with "No history yet"
            out = out.replace("{% if sessions %}", "").replace("{% for s in sessions %}", "")
            out = out.replace("{% endfor %}", "").replace("{% else %}", "")
            out = out.replace("{% endif %}", "")
    return HTMLResponse(content=out, status_code=200)

def _render_metrics_page(metrics: Dict[str, float | int], stats: Dict[str, float | int]) -> HTMLResponse:
    """
    Render METRICS_HTML by replacing {{ metrics.* }} and the stats for-loop.
    """
    html = METRICS_HTML

    # Replace simple {{ metrics.* }} placeholders
    replacements = {
        "{{ metrics.scrub_count }}": str(metrics.get("scrub_count", 0)),
        "{{ metrics.entities_detected_total }}": str(metrics.get("entities_detected_total", 0)),
        "{{ metrics.access_denied_count }}": str(metrics.get("access_denied_count", 0)),
    }
    for k, v in replacements.items():
        html = html.replace(k, v)

    # Replace the {% for key, value in stats.items() %} ... {% endfor %} block
    start_tag = "{% for key, value in stats.items() %}"
    end_tag = "{% endfor %}"

    if start_tag in html and end_tag in html:
        start = html.index(start_tag)
        end = html.index(end_tag, start) + len(end_tag)

        rows = []
        for key, value in stats.items():
            label = key.replace("_", " ").title()
            rows.append(
                f'''
                <div class="flex justify-between border-b py-2">
                    <span class="text-gray-600">{label}</span>
                    <span class="font-bold">{value}</span>
                </div>
                '''.strip()
            )
        rows_html = "\n".join(rows)

        html = html[:start] + rows_html + html[end:]

    return HTMLResponse(content=html, status_code=200)


@app.get("/login")
def login_page():
    return _html(LOGIN_HTML)

@app.post("/login")
async def login(request: Request):
    data = await request.json()
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    user = USERS.get(username)
    if not user or user["password"] != password:
        return JSONResponse({"error": "Invalid username or password"}, status_code=401)
    resp = RedirectResponse(url="/", status_code=303)
    resp.set_cookie("sp_user", username, httponly=True, samesite="lax")
    return resp

@app.get("/register")
def register_page():
    return _html(REGISTER_HTML)

@app.post("/register")
async def register(request: Request):
    data = await request.json()
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()
    if not username or not email or not password:
        return JSONResponse({"error": "All fields are required"}, status_code=400)
    if username in USERS:
        return JSONResponse({"error": "Username already exists"}, status_code=400)
    USERS[username] = {"username": username, "email": email, "password": password}
    return JSONResponse({"ok": True})

@app.post("/api/logout")
async def api_logout(response: Response):
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("sp_user")
    return resp

@app.get("/")
def dashboard(user: Optional[str] = Depends(require_user)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return _html(DASHBOARD_HTML)

@app.get("/history")
def history(user: Optional[str] = Depends(require_user)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    user_sessions = [s for s in HISTORY if s["username"] == user]
    return _html(HISTORY_HTML, sessions=user_sessions)


@app.get("/metrics")
def metrics(user: Optional[str] = Depends(require_user)):
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    total_scrubs = len(HISTORY)
    entities_total = sum(s["entity_count"] for s in HISTORY) if total_scrubs else 0
    avg_conf = (
        round(100 * (sum(s["confidence_score"] for s in HISTORY) / total_scrubs), 2)
        if total_scrubs else 0
    )
    last_activity = HISTORY[-1]["created_at"] if total_scrubs else "—"

    metrics_values = {
        "scrub_count": total_scrubs,
        "entities_detected_total": entities_total,
        "access_denied_count": 0,  # update if you implement RBAC/ACL
    }
    stats_values = {
        "avg_entities_per_scrub": round(entities_total / total_scrubs, 2) if total_scrubs else 0,
        "avg_confidence_percent": avg_conf,
        "unique_users": len({s["username"] for s in HISTORY}),
        "last_activity": last_activity,
    }

    return _render_metrics_page(metrics_values, stats_values)



@app.post("/api/scrub")
async def api_scrub(request: Request, user: Optional[str] = Depends(require_user)):
    if not user:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    data = await request.json()
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        return JSONResponse({"error": "Prompt is required"}, status_code=400)

    scrubbed, entities = scrubber.scrub_text(prompt, user_id=user)
    confidence = 0.0
    if entities:
        confidence = sum(e.get("confidence", 0.9) for e in entities) / len(entities)

    # Persist to history
    HISTORY.append({
        "username": user,
        "scrubbed_prompt": scrubbed,
        "entity_count": len(entities),
        "confidence_score": confidence,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

    return JSONResponse({
        "scrubbed_content": scrubbed,
        "entity_count": len(entities),
        "confidence_score": confidence,
        "entities": entities
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app_combined:app", host="127.0.0.1", port=8000, reload=False)
