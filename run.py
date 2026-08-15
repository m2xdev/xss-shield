import logging
from logging.handlers import RotatingFileHandler
import secrets
import base64
from flask import Flask, request, g

import html
import nh3

def strip_xss(content: str) -> str:
    if not isinstance(content, str):
        return ""
    # Очищаем HTML с помощью библиотеки nh3
    cleaned = nh3.clean(content)
    return cleaned

app = Flask(__name__)

# ============================================================
# НАСТРОЙКА БЕЗОПАСНОГО ЛОГИРОВАНИЯ (RotatingFileHandler)
# ============================================================
handler = RotatingFileHandler('xss_attacks.log', maxBytes=1_000_000, backupCount=3)
handler.setLevel(logging.WARNING)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

app.logger.addHandler(handler)
app.logger.setLevel(logging.WARNING)

def log_attack(data, clean_data):
    if clean_data != data:
        app.logger.warning(f"🚨 XSS Attack blocked! Input: {data} | Sanitized: {clean_data}")

# ============================================================
# CSP С NONCE НА КАЖДЫЙ ЗАПРОС
# ============================================================
@app.before_request
def before_request():
    g.csp_nonce = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')

@app.after_request
def add_security_headers(response):
    nonce = getattr(g, 'csp_nonce', '')
    response.headers['Content-Security-Policy'] = f"default-src 'self'; script-src 'self' 'nonce-{nonce}';"
    return response

# ============================================================
# ГЛАВНАЯ СТРАНИЦА
# ============================================================
@app.route('/')
def index():
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>🛡️ XSS-Lab with nh3</title>
        <style>
            body {{ font-family: Arial; max-width: 800px; margin: 50px auto; }}
            .vuln {{ background: #ffebee; border-left: 5px solid #e53935; padding: 20px; margin: 20px 0; }}
            .safe {{ background: #e8f5e9; border-left: 5px solid #43a047; padding: 20px; margin: 20px 0; }}
            .box {{ border: 1px solid #ddd; padding: 20px; margin: 20px 0; border-radius: 8px; }}
            input, textarea {{ width: 100%; padding: 10px; margin: 5px 0; border: 1px solid #ddd; border-radius: 4px; }}
            button {{ background: #4285f4; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }}
            pre {{ background: #f5f5f5; padding: 15px; border-radius: 4px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <h1>🛡️ XSS-Lab with <span style="color:#4285f4;">nh3</span></h1>
        <p><strong>Полигон для XSS-атак и защиты с использованием nh3 и CSP</strong></p>

        <div class="box">
            <h2>🎯 Доступные уязвимости:</h2>
            <ul>
                <li><a href="/vuln/reflected?q=test"><strong>Reflected XSS</strong></a> — уязвимый поиск</li>
                <li><a href="/secure/reflected?q=test"><strong>Reflected XSS (защищённый)</strong></a> — поиск с nh3</li>
                <li><a href="/vuln/stored"><strong>Stored XSS</strong></a> — комментарии без защиты</li>
                <li><a href="/secure/stored"><strong>Stored XSS (защищённый)</strong></a> — комментарии с nh3</li>
                <li><a href="/vuln/dom"><strong>DOM-based XSS</strong></a> — уязвимость на клиенте (innerHTML)</li>
                <li><a href="/secure/dom#%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"><strong>DOM-based XSS (защищённый)</strong></a> — с textContent</li>
            </ul>
        </div>

        <hr>
        <p><small>🛡️ Powered by <strong>nh3</strong> & <strong>CSP Nonce</strong></small></p>
    </body>
    </html>
    """

# ============================================================
# УЯЗВИМАЯ ВЕРСИЯ: Reflected XSS (без защиты)
# ============================================================
@app.route('/vuln/reflected')
def vuln_reflected():
    q = request.args.get('q', '')
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>⚠️ Reflected XSS (уязвимый)</title></head>
    <body style="font-family:Arial;max-width:800px;margin:50px auto;">
        <h1 style="color:#e53935;">⚠️ Уязвимый поиск</h1>
        <div style="background:#ffebee;padding:20px;border-radius:8px;">
            <p><strong>Результат поиска:</strong> {q}</p>
        </div>
        <form>
            <input type="text" name="q" placeholder="Введите запрос">
            <button type="submit">Искать</button>
        </form>
        <p><a href="/">← Назад</a></p>
    </body>
    </html>
    """

# ============================================================
# ЗАЩИЩЁННАЯ ВЕРСИЯ: Reflected XSS (с nh3 + логированием)
# ============================================================
@app.route('/secure/reflected')
def secure_reflected():
    q = request.args.get('q', '')
    clean_q = strip_xss(q)
    log_attack(q, clean_q)
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>✅ Reflected XSS (защищён)</title></head>
    <body style="font-family:Arial;max-width:800px;margin:50px auto;">
        <h1 style="color:#43a047;">✅ Защищённый поиск</h1>
        <div style="background:#e8f5e9;padding:20px;border-radius:8px;">
            <p><strong>Результат поиска:</strong> {clean_q}</p>
        </div>
        <form>
            <input type="text" name="q" placeholder="Введите запрос">
            <button type="submit">Искать</button>
        </form>
        <p><a href="/">← Назад</a></p>
        <p style="color:#43a047;">✅ strip_xss очистил ввод, попытка залогирована.</p>
    </body>
    </html>
    """

# ============================================================
# УЯЗВИМАЯ ВЕРСИЯ: Stored XSS (без защиты)
# ============================================================
vuln_comments = []

@app.route('/vuln/stored', methods=['GET', 'POST'])
def vuln_stored():
    global vuln_comments
    if request.method == 'POST':
        text = request.form.get('text', '')
        vuln_comments.append(text)

    html_comments = "".join([f"<div style='border:1px solid #ccc;padding:10px;margin:5px;'>{c}</div>" for c in vuln_comments])

    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>⚠️ Stored XSS (уязвимый)</title></head>
    <body style="font-family:Arial;max-width:800px;margin:50px auto;">
        <h1 style="color:#e53935;">⚠️ Уязвимые комментарии</h1>
        <form method="POST">
            <input type="text" name="text" placeholder="Введите комментарий">
            <button type="submit">Отправить</button>
        </form>
        <hr>
        <h2>Все комментарии:</h2>
        {html_comments}
        <p><a href="/">← Назад</a></p>
    </body>
    </html>
    """

# ============================================================
# ЗАЩИЩЁННАЯ ВЕРСИЯ: Stored XSS (с nh3 + логированием)
# ============================================================
secure_comments = []

@app.route('/secure/stored', methods=['GET', 'POST'])
def secure_stored():
    global secure_comments
    if request.method == 'POST':
        text = request.form.get('text', '')
        clean_text = strip_xss(text)
        log_attack(text, clean_text)
        secure_comments.append(clean_text)

    html_comments = "".join([f"<div style='border:1px solid #ccc;padding:10px;margin:5px;'>{c}</div>" for c in secure_comments])

    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>✅ Stored XSS (защищён)</title></head>
    <body style="font-family:Arial;max-width:800px;margin:50px auto;">
        <h1 style="color:#43a047;">✅ Защищённые комментарии</h1>
        <form method="POST">
            <input type="text" name="text" placeholder="Введите комментарий">
            <button type="submit">Отправить</button>
        </form>
        <hr>
        <h2>Все комментарии (безопасные):</h2>
        {html_comments}
        <p><a href="/">← Назад</a></p>
    </body>
    </html>
    """

# ============================================================
# DOM-based XSS (Уязвимый через innerHTML)
# ============================================================
@app.route('/vuln/dom')
def vuln_dom():
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>⚠️ DOM-based XSS</title></head>
    <body style="font-family:Arial;max-width:800px;margin:50px auto;">
        <h1 style="color:#e53935;">⚠️ DOM-based XSS</h1>
        <p>Введи что-то в URL после <code>#</code></p>
        <div id="output" style="background:#f5f5f5;padding:20px;border-radius:8px;"></div>
        <script nonce="{g.csp_nonce}">
            var hash = window.location.hash.substring(1);
            document.getElementById('output').innerHTML = hash;
        </script>
        <p><a href="/">← Назад</a></p>
    </body>
    </html>
    """

# ============================================================
# ЗАЩИЩЁННАЯ ВЕРСИЯ: DOM-based XSS (с textContent)
# ============================================================
@app.route('/secure/dom')
def secure_dom():
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>✅ DOM-based XSS (защищён)</title></head>
    <body style="font-family:Arial;max-width:800px;margin:50px auto;">
        <h1 style="color:#43a047;">✅ DOM-based XSS (Защищено)</h1>
        <p>Данные из URL: <code id="output"></code></p>
        <script nonce="{g.csp_nonce}">
            var hash = window.location.hash.substring(1);
            document.getElementById('output').textContent = hash;
        </script>
        <p><a href="/">← Назад</a></p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)