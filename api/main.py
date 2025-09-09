# api/main.py
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
import sqlite3
import html

app = FastAPI(title="DIO - Simulação de Vulnerabilidades")

# Caminho do banco de dados (arquivo simples SQLite)
DB_PATH = "api/demo.db"

# Função para iniciar o banco com uma tabela simples
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        full_name TEXT
    )
    """)
    # adiciona um usuário exemplo
    c.execute("INSERT OR IGNORE INTO users(id, username, full_name) VALUES (1, 'antonio', 'Antonio A. F. Castro')")
    conn.commit()
    conn.close()

# Inicializa o banco quando a API sobe
@app.on_event("startup")
def startup_event():
    init_db()

# Endpoint inicial
@app.get("/", response_class=JSONResponse)
def read_root():
    return {"message": "API de estudo de vulnerabilidades - execute apenas localmente"}

# ---------------- DEMONSTRAÇÃO VULNERÁVEL ----------------
@app.get("/vulnerable/reflect", response_class=HTMLResponse)
def vulnerable_reflect(text: str = ""):
    """
    Este endpoint é vulnerável a XSS refletido.
    Ele insere diretamente o texto do usuário no HTML sem tratar.
    NÃO use em produção.
    """
    html_body = f"""
    <html>
      <head><title>Reflect Demo</title></head>
      <body>
        <h3>Reflect endpoint (vulnerável)</h3>
        <div>Você enviou: {text}</div>
        <p>Teste localmente com <code>?text=teste</code></p>
        <p>Exemplo de ataque: <code>?text=&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
      </body>
    </html>
    """
    return HTMLResponse(content=html_body)

# ---------------- VERSÃO SEGURA ----------------
@app.get("/safe/reflect", response_class=HTMLResponse)
def safe_reflect(text: str = ""):
    """
    Versão segura: faz o escape do texto antes de mostrar no HTML.
    """
    safe_text = html.escape(text)
    html_body = f"""
    <html>
      <head><title>Safe Reflect</title></head>
      <body>
        <h3>Reflect endpoint (seguro)</h3>
        <div>Você enviou: {safe_text}</div>
      </body>
    </html>
    """
    return HTMLResponse(content=html_body)

# ---------------- CONSULTA AO BANCO ----------------
@app.get("/users", response_class=JSONResponse)
def list_users(q: str = ""):
    """
    Lista usuários cadastrados no banco.
    A consulta é feita com parâmetros (forma segura contra SQL Injection).
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, full_name FROM users WHERE username LIKE ?", (f"%{q}%",))
    rows = c.fetchall()
    conn.close()

    users = [{"id": r[0], "username": r[1], "full_name": r[2]} for r in rows]
    return {"count": len(users), "users": users}
