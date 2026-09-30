"""
VulnBank — a deliberately vulnerable Flask web app.

WARNING: This application is intentionally insecure. It exists only as a
target for the companion scanner in ../scanner. Never deploy it anywhere
reachable from the internet, and never point real credentials at it.

Vulnerabilities implemented (all genuinely exploitable, not simulated):
  1. SQL Injection       - /login  (string-concatenated SQL query)
  2. Reflected XSS        - /search (unescaped user input in HTML response)
  3. Command Injection    - /ping   (user input passed to a shell command)
  4. Path Traversal       - /download (unsanitized filename joined to a dir)
  5. IDOR                 - /invoice/<id> (no ownership check)
  6. Open Redirect        - /goto?next=... (unsanitized redirect target)
"""
import os
import sqlite3
import subprocess

from flask import Flask, request, redirect, Response, g

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vulnbank.db")
FILES_DIR = os.path.join(BASE_DIR, "files")
SENTINEL_FILE = os.path.join(FILES_DIR, "sentinel.txt")
SENTINEL_MARKER = "VULNBANK-SENTINEL-4f9c2a"

app = Flask(__name__)


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
    return db


@app.teardown_appcontext
def close_db(exception=None):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(FILES_DIR, exist_ok=True)
    first_time = not os.path.exists(DB_PATH)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_username TEXT NOT NULL,
            amount TEXT NOT NULL,
            memo TEXT NOT NULL
        );
        """
    )
    if first_time:
        cur.executemany(
            "INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)",
            [
                ("alice", "alicepw123", 0),
                ("bob", "bobpw456", 0),
                ("admin", "sup3rSecretAdminPW!", 1),
            ],
        )
        cur.executemany(
            "INSERT INTO invoices (owner_username, amount, memo) VALUES (?, ?, ?)",
            [
                ("alice", "120.00", "Consulting - January"),
                ("bob", "45.50", "Widget purchase"),
                ("admin", "9999.99", "Internal admin payout"),
            ],
        )
    conn.commit()
    conn.close()
    if not os.path.exists(SENTINEL_FILE):
        with open(SENTINEL_FILE, "w") as f:
            f.write(f"{SENTINEL_MARKER}\nThis file lives in the app's public download directory.\n")


INDEX_HTML = """
<!doctype html>
<html><head><title>VulnBank</title></head>
<body>
<h1>VulnBank (intentionally vulnerable demo app)</h1>
<ul>
  <li><a href="/login">Login</a></li>
  <li><a href="/search?q=test">Search</a></li>
  <li><a href="/ping?host=127.0.0.1">Ping a host</a></li>
  <li><a href="/download?file=sentinel.txt">Download a file</a></li>
  <li><a href="/invoice/1">View an invoice</a></li>
  <li><a href="/goto?next=/">Redirect example</a></li>
</ul>
</body></html>
"""


@app.route("/")
def index():
    return INDEX_HTML


# ---------------------------------------------------------------------------
# 1. SQL Injection — /login
# ---------------------------------------------------------------------------
LOGIN_FORM = """
<!doctype html>
<html><body>
<h1>Login</h1>
<form method="POST" action="/login">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <input type="submit" value="Login">
</form>
{result}
</body></html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return LOGIN_FORM.format(result="")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABLE: string-concatenated SQL query, classic SQL injection.
    query = "SELECT id, username, is_admin FROM users WHERE username = '%s' AND password = '%s'" % (
        username,
        password,
    )
    db = get_db()
    cur = db.cursor()
    try:
        cur.execute(query)
        row = cur.fetchone()
    except sqlite3.Error as e:
        # Deliberately leak the DB error, a common real-world SQLi signature.
        return LOGIN_FORM.format(result=f"<p>Database error: {e}</p>"), 500

    if row:
        result = f"<p>Welcome, {row[1]}! (id={row[0]}, admin={bool(row[2])})</p>"
        return LOGIN_FORM.format(result=result)
    return LOGIN_FORM.format(result="<p>Invalid credentials</p>"), 401


# ---------------------------------------------------------------------------
# 2. Reflected XSS — /search
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULNERABLE: user input is dropped straight into the HTML response
    # with no escaping at all.
    return f"""
    <!doctype html>
    <html><body>
      <h1>Search results</h1>
      <p>You searched for: {q}</p>
      <p>No matching transactions found.</p>
    </body></html>
    """


# ---------------------------------------------------------------------------
# 3. Command Injection — /ping
# ---------------------------------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULNERABLE: user input is interpolated directly into a shell command.
    cmd = "ping -c 1 " + host
    try:
        output = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        )
        body = output.stdout + output.stderr
    except subprocess.TimeoutExpired:
        body = "(command timed out)"
    return Response(f"<pre>{body}</pre>", mimetype="text/html")


# ---------------------------------------------------------------------------
# 4. Path Traversal — /download
# ---------------------------------------------------------------------------
@app.route("/download")
def download():
    filename = request.args.get("file", "sentinel.txt")
    # VULNERABLE: no sanitization of '..' — allows escaping FILES_DIR.
    path = os.path.join(FILES_DIR, filename)
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read()
        return Response(content, mimetype="text/plain")
    except (IOError, OSError) as e:
        return Response(f"Error reading file: {e}", status=404, mimetype="text/plain")


# ---------------------------------------------------------------------------
# 5. IDOR — /invoice/<id>
# ---------------------------------------------------------------------------
@app.route("/invoice/<int:invoice_id>")
def invoice(invoice_id):
    # VULNERABLE: no session/auth check that the caller owns this invoice —
    # any id can be enumerated to read anyone else's invoice.
    db = get_db()
    cur = db.cursor()
    cur.execute(
        "SELECT id, owner_username, amount, memo FROM invoices WHERE id = ?",
        (invoice_id,),
    )
    row = cur.fetchone()
    if not row:
        return "Invoice not found", 404
    return f"""
    <!doctype html>
    <html><body>
      <h1>Invoice #{row[0]}</h1>
      <p>Owner: {row[1]}</p>
      <p>Amount: ${row[2]}</p>
      <p>Memo: {row[3]}</p>
    </body></html>
    """


# ---------------------------------------------------------------------------
# 6. Open Redirect — /goto
# ---------------------------------------------------------------------------
@app.route("/goto")
def goto():
    next_url = request.args.get("next", "/")
    # VULNERABLE: redirects to any attacker-supplied URL, no allowlist check.
    return redirect(next_url)


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=False)
