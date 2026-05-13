import os
import json
import sqlite3
import secrets
from datetime import datetime
from urllib.parse import urlparse

import bcrypt
from flask import (Flask, render_template, request, redirect, session,
                   url_for, send_from_directory, abort, make_response, flash)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from markupsafe import escape

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

csrf = CSRFProtect(app)
limiter = Limiter(key_func=get_remote_address, app=app, default_limits=[])


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; object-src 'none'; base-uri 'self';"
    )
    return response


USERS = {
    "admin": {"password": "anchieta123", "role": "administrator"},
    "analista": {"password": "cyber2026", "role": "security_analyst"},
}

REPORTS = {
    1: {"owner": "Equipe Alpha", "title": "Relatório Interno 01", "content": "Checklist de exposição de portas e serviços."},
    2: {"owner": "Equipe Beta", "title": "Relatório Interno 02", "content": "Não deixar diretórios sensíveis acessíveis."},
    3: {"owner": "Equipe Gama", "title": "Relatório Interno 03", "content": "Evitar credenciais padrão em produção."},
}

USERS_FILE = os.path.join(app.root_path, "users.json")
BACKUP_DIR = os.path.join(app.root_path, "static", "backup")
ACCESS_DB_PATH = os.path.join(app.root_path, "access_logs.db")
DATA_DB_PATH = os.path.join(app.root_path, "corp_data.db")

ALLOWED_HOSTS = {"127.0.0.1", "localhost", "anchieta.lab"}

XSS_PATTERNS = ["<script", "javascript:", "onerror=", "onload=", "alert(", "<img", "<svg", "document.cookie", "eval(", "onclick="]


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def check_password(plain: str, stored: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), stored.encode())
    except Exception:
        return False


def is_bcrypt_hash(value: str) -> bool:
    return value.startswith(("$2b$", "$2a$", "$2y$"))


def seed_users_file():
    if not os.path.exists(USERS_FILE):
        hashed = {
            username: {"password": hash_password(data["password"]), "role": data["role"]}
            for username, data in USERS.items()
        }
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(hashed, f, ensure_ascii=False, indent=2)


def migrate_passwords():
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        users = json.load(f)

    changed = False
    for username, data in users.items():
        if not is_bcrypt_hash(data["password"]):
            data["password"] = hash_password(data["password"])
            changed = True

    if changed:
        with open(USERS_FILE, "w", encoding="utf-8") as f:
            json.dump(users, f, ensure_ascii=False, indent=2)


def load_users():
    seed_users_file()
    migrate_passwords()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)


def get_data_connection():
    conn = sqlite3.connect(DATA_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = sqlite3.connect(ACCESS_DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS access_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            user_agent TEXT,
            path TEXT,
            method TEXT,
            consent INTEGER,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()


def get_client_ip():
    return request.remote_addr or "desconhecido"


def require_login():
    if "user" not in session:
        return redirect(url_for("painel"))
    return None


def require_admin_role():
    guard = require_login()
    if guard:
        return guard
    users = load_users()
    if users.get(session["user"], {}).get("role") != "administrator":
        abort(403)
    return None


@app.before_request
def register_access():
    if request.path.startswith("/static/"):
        sensitive = ("/static/backup/", "/static/config/")
        if any(request.path.startswith(p) for p in sensitive):
            if "user" not in session:
                abort(403)
        return

    consent = 1 if request.cookies.get("anchieta_cookie_consent") == "accepted" else 0
    conn = sqlite3.connect(ACCESS_DB_PATH)
    conn.execute(
        "INSERT INTO access_log (ip, user_agent, path, method, consent, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            get_client_ip(),
            request.headers.get("User-Agent", "")[:300],
            request.path,
            request.method,
            consent,
            datetime.utcnow().isoformat(timespec="seconds") + "Z",
        ),
    )
    conn.commit()
    conn.close()


init_db()


@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


@app.errorhandler(429)
def too_many_requests(e):
    return render_template("429.html"), 429


@app.route("/")
def index():
    news = [
        {"title": "Laboratório Anchieta v2.6 liberado", "tag": "NOVO"},
        {"title": "Painel interno com métricas em tempo real", "tag": "LAB"},
        {"title": "Documentos históricos preservados para auditoria", "tag": "INFO"},
    ]
    return render_template("index.html", news=news)


@app.route("/search")
def search():
    q = request.args.get("q", "").lower()

    if any(p in q for p in XSS_PATTERNS):
        return render_template("search.html", q=q, sample=[], prova=None, zoeira=True)

    sample = [
        "Mapa de rede local",
        "Checklist de auditoria",
        "Documentação do portal",
        "Guia rápido de acesso interno",
    ]

    prova_result = None

    if "prova" in q:
        prova_result = {
            "title": "Documento interno - Avaliação de Cybersegurança",
            "content": "Achou mesmo que eu ia colocar a prova aqui? Sério?"
        }
    if "060185" in q:
        prova_result = {
            "title": "PROVA CYBERSEGURANÇA",
            "content": """
Instruções
Leia o cenário com atenção. As respostas devem ser inseridas no final do relatório da parte 1 da tarefa.

## QUESTÃO 1

Durante a análise de um sistema web corporativo, um analista de segurança identifica que o servidor disponibiliza uma página de status contendo informações como framework utilizado, ambiente de execução e detalhes do servidor web. Embora essas informações não permitam, por si só, a exploração direta do sistema, elas podem ser utilizadas como base para etapas posteriores do ataque.

Considerando esse cenário, qual é o principal risco associado à exposição dessas informações?

A) Permitir a execução direta de código no servidor
B) Facilitar a enumeração e identificação de tecnologias para exploração posterior
C) Garantir a integridade dos dados armazenados no sistema
D) Impedir ataques de força bruta
E) Substituir mecanismos de autenticação

---

## QUESTÃO 2

Em um sistema web, foi identificado que determinados diretórios, como `/backup` e `/static/config`, estão acessíveis sem autenticação, contendo arquivos sensíveis, como bases de dados e configurações internas.

Do ponto de vista de segurança da informação, essa situação representa principalmente:

A) Um problema de desempenho do servidor
B) Um erro de lógica na aplicação cliente
C) Uma falha de controle de acesso e exposição de dados sensíveis
D) Um problema de compatibilidade entre navegadores
E) Uma limitação do protocolo HTTP

---

## QUESTÃO 3

Durante um teste de segurança, um estudante percebe que a aplicação exibe diretamente, na página de resultados de busca, o valor digitado pelo usuário, sem qualquer tipo de tratamento ou validação.

Considerando boas práticas de desenvolvimento seguro, essa implementação pode resultar em:

A) Aumento da performance da aplicação
B) Vulnerabilidade de execução remota no servidor
C) Vulnerabilidade de Cross-Site Scripting (XSS)
D) Falha de conexão com o banco de dados
E) Erro de compilação no backend

---

## QUESTÃO 4

Uma aplicação web possui um painel administrativo acessível via login. Durante a análise, verificou-se que as credenciais utilizadas são simples e previsíveis, como "admin/admin123".

Esse tipo de problema está mais diretamente relacionado a:

A) Criptografia forte de dados
B) Políticas inadequadas de autenticação
C) Falha de roteamento de rede
D) Configuração incorreta de firewall
E) Uso excessivo de memória

---

## QUESTÃO 5

Durante a navegação no sistema, um usuário autenticado consegue acessar registros de outros usuários apenas alterando um parâmetro na URL, como `id`.

Esse comportamento caracteriza:

A) SQL Injection
B) Cross-Site Request Forgery (CSRF)
C) Insecure Direct Object Reference (IDOR)
D) Denial of Service (DoS)
E) Clickjacking

---

## QUESTÃO 6

Ao analisar os logs de acesso de uma aplicação, um estudante identifica múltiplas requisições vindas de diferentes IPs tentando acessar a área administrativa com diversas combinações de usuário e senha.

Esse comportamento é característico de:

A) Ataque de força bruta
B) Ataque de injeção SQL
C) Ataque de phishing
D) Ataque de spoofing
E) Ataque de sniffing

---

## QUESTÃO 7

Um endpoint interno da aplicação (`/internal-api`) está acessível publicamente, retornando informações sobre o sistema e seu estado.

Esse tipo de exposição pode ser classificado como:

A) Boa prática de transparência
B) Exposição indevida de interface interna
C) Técnica de otimização de rede
D) Mecanismo de autenticação
E) Estratégia de backup

---

## QUESTÃO 8

Em relação ao tratamento de entradas fornecidas pelo usuário, qual das alternativas representa uma prática adequada de segurança?

A) Confiar que o usuário não irá inserir dados maliciosos
B) Exibir diretamente qualquer entrada do usuário
C) Aplicar validação e escape conforme o contexto de uso
D) Ignorar entradas muito grandes
E) Armazenar todas as entradas sem tratamento

---

## QUESTÃO 9

Uma aplicação armazena senhas de usuários em texto puro em um arquivo JSON.

Essa prática é considerada inadequada porque:

A) Aumenta o consumo de memória
B) Dificulta o acesso ao sistema
C) Compromete a confidencialidade das credenciais
D) Reduz a velocidade da aplicação
E) Impede o funcionamento do login

---

## QUESTÃO 10

Um analista propõe a implementação de uma política de segurança que inclua revisão de código, testes de segurança e correção de vulnerabilidades ao longo do ciclo de desenvolvimento.

Essa abordagem está relacionada a:

A) Desenvolvimento inseguro
B) DevOps tradicional
C) Secure Software Development Lifecycle (SSDLC)
D) Virtualização de servidores
E) Gerenciamento de banco de dados
"""
        }
    return render_template("search.html", q=q, sample=sample, prova=prova_result, zoeira=False)


@app.route("/xss-lab")
def xss_lab():
    payload = request.args.get("payload", "")
    return render_template("xss_lab.html", payload=escape(payload), raw_payload=payload)


@app.route("/code-review/search")
def code_review_search():
    snippet = '''
# Exemplo didático de antipadrão (NÃO usar em produção)
# resultado = f"<h3>{q}</h3>"  # risco de XSS se renderizado sem escape

# Versão segura usada neste laboratório:
from markupsafe import escape
resultado = f"<h3>{escape(q)}</h3>"
'''
    return render_template("code_review.html", snippet=snippet)


@app.route("/security-notes")
def security_notes():
    notes = [
        "Campos de busca e comentários exigem escape/sanitização no backend e no frontend.",
        "innerHTML com dados do usuário é um antipadrão frequente em falhas DOM-based XSS.",
        "CSP ajuda a reduzir impacto, mas não substitui validação e escape corretos.",
        "Dados refletidos devem ser tratados conforme o contexto HTML, atributo, URL ou JavaScript."
    ]
    return render_template("security_notes.html", notes=notes)


@app.route("/robots.txt")
def robots():
    return send_from_directory(os.path.join(app.root_path, "static"), "robots.txt")


@app.route("/cookie-consent/<choice>")
def cookie_consent(choice):
    referrer = request.referrer or ""
    parsed = urlparse(referrer)
    if parsed.netloc.split(":")[0] in ALLOWED_HOSTS:
        redirect_url = referrer
    else:
        redirect_url = url_for("index")

    response = make_response(redirect(redirect_url))
    value = "accepted" if choice == "accept" else "rejected"
    response.set_cookie("anchieta_cookie_consent", value, max_age=60 * 60 * 24 * 30, samesite="Lax")
    return response


@app.route("/admin")
def admin():
    return render_template("fake_admin.html")


@app.route("/painel-anchieta", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def painel():
    if "user" in session:
        return redirect(url_for("dashboard"))
    error = None
    zoeira = False
    if request.method == "POST":
        username = request.form.get("username", "")
        pwd = request.form.get("password", "")
        users = load_users()
        if username in users and check_password(pwd, users[username]["password"]):
            session["user"] = username
            return redirect(url_for("dashboard"))
        error = "Credenciais inválidas."
        zoeira = True
    return render_template("admin.html", error=error, zoeira=zoeira)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    guard = require_login()
    if guard:
        return guard
    users = load_users()
    return render_template("dashboard.html", user=session["user"], role=users[session["user"]]["role"])


@app.route("/profile")
def profile():
    guard = require_login()
    if guard:
        return guard
    user_id = request.args.get("id", "1")
    profiles = {
        "1": {"name": "Equipe Alpha", "sector": "SOC", "email": "alpha@anchieta.lab"},
        "2": {"name": "Equipe Beta", "sector": "Blue Team", "email": "beta@anchieta.lab"},
        "3": {"name": "Equipe Gama", "sector": "Red Team", "email": "gama@anchieta.lab"},
    }
    if user_id not in profiles:
        return render_template("profile.html", profile=None, user_id=user_id, zoeira=True)
    profile_data = profiles.get(user_id, profiles["1"])
    return render_template("profile.html", profile=profile_data, user_id=user_id, zoeira=False)


@app.route("/report/<int:report_id>")
def report(report_id):
    guard = require_login()
    if guard:
        return guard
    report_data = REPORTS.get(report_id)
    if not report_data:
        abort(404)
    return render_template("report.html", report=report_data, report_id=report_id)


@app.route("/records")
def records():
    guard = require_login()
    if guard:
        return guard
    conn = get_data_connection()
    employees = conn.execute(
        "SELECT id, full_name, department, email, extension, badge_id, access_level FROM employees ORDER BY id"
    ).fetchall()
    conn.close()
    return render_template("records.html", employees=employees)


@app.route("/tickets")
def tickets():
    guard = require_login()
    if guard:
        return guard
    conn = get_data_connection()
    ticket_list = conn.execute(
        "SELECT id, employee_name, subject, status, notes FROM support_tickets ORDER BY id DESC"
    ).fetchall()
    conn.close()
    return render_template("tickets.html", tickets=ticket_list)


@app.route("/server-status")
def status():
    guard = require_login()
    if guard:
        return guard
    data = {
        "framework": "Flask 3.x (dev)",
        "server": "Werkzeug dev server",
        "environment": "laboratorio",
        "debug": False,
        "port": 5000,
        "notes": "Monitoramento temporariamente exposto para testes."
    }
    return render_template("status.html", data=data)


@app.route("/backup/")
def backup_index():
    guard = require_login()
    if guard:
        return guard
    files = sorted(os.listdir(BACKUP_DIR))
    return render_template("backup.html", files=files)


@app.route("/backup/<path:filename>")
def backup_file(filename):
    guard = require_login()
    if guard:
        return guard
    return send_from_directory(BACKUP_DIR, filename, as_attachment=False)


@app.route("/internal-api")
def internal_api():
    guard = require_login()
    if guard:
        return guard
    return {
        "status": "active",
        "message": "endpoint de teste ainda habilitado",
        "version": "dev-0.9",
        "note": "remover antes da versão final"
    }


@app.route("/api/health")
def health():
    guard = require_login()
    if guard:
        return guard
    return {
        "status": "ok",
        "service": "Laboratório Anchieta",
        "version": "2.6-lab",
    }


@app.route("/access_log")
def access_log():
    guard = require_login()
    if guard:
        return guard
    conn = sqlite3.connect(ACCESS_DB_PATH)
    rows = conn.execute(
        "SELECT ip, user_agent, path, method, consent, created_at FROM access_log ORDER BY id DESC LIMIT 100"
    ).fetchall()
    conn.close()
    logs = [
        {
            "ip": row[0],
            "user_agent": row[1],
            "path": row[2],
            "method": row[3],
            "consent": "sim" if row[4] else "não",
            "created_at": row[5],
        }
        for row in rows
    ]
    return render_template("access_log.html", logs=logs)


@app.route("/admin/users", methods=["GET", "POST"])
def admin_users():
    guard = require_admin_role()
    if guard:
        return guard

    users = load_users()

    if request.method == "POST":
        action = request.form.get("action", "create")

        if action == "create":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()
            role = request.form.get("role", "security_analyst").strip()

            if not username or not password:
                flash("Preencha usuário e senha.", "error")
            elif username in users:
                flash("Esse usuário já existe.", "error")
            else:
                users[username] = {"password": hash_password(password), "role": role}
                save_users(users)
                flash(f"Usuário '{username}' criado com sucesso.", "success")
                return redirect(url_for("admin_users"))

        elif action == "delete":
            username = request.form.get("target_user", "").strip()
            if username == session.get("user"):
                flash("Você não pode excluir o usuário logado.", "error")
            elif username not in users:
                flash("Usuário não encontrado.", "error")
            else:
                users.pop(username)
                save_users(users)
                flash(f"Usuário '{username}' removido com sucesso.", "success")
                return redirect(url_for("admin_users"))

        elif action == "update_password":
            username = request.form.get("target_user", "").strip()
            new_password = request.form.get("new_password", "").strip()
            if username not in users:
                flash("Usuário não encontrado.", "error")
            elif not new_password:
                flash("Informe a nova senha.", "error")
            else:
                users[username]["password"] = hash_password(new_password)
                save_users(users)
                flash(f"Senha de '{username}' atualizada.", "success")
                return redirect(url_for("admin_users"))

    users_list = [
        {"username": u, "role": d.get("role", "security_analyst")}
        for u, d in sorted(users.items())
    ]
    return render_template("admin_users.html", users_list=users_list)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    host = "0.0.0.0" if os.environ.get("RENDER") else "127.0.0.1"
    app.run(host=host, port=port, debug=False)
