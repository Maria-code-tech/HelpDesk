import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "my-secret-key"
DB_NAME = "helpdesk.db"


# --- Работа с базой данных ---

def get_db():
    """Создает и возвращает подключение к БД."""
    db = sqlite3.connect(DB_NAME)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    """Инициализирует таблицы и проверяет структуру БД."""
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Новая',
                user_id INTEGER
            )
        """)

        # Проверка миграции для старых версий БД
        columns = [col["name"] for col in db.execute("PRAGMA table_info(tickets)").fetchall()]
        if "user_id" not in columns:
            db.execute("ALTER TABLE tickets ADD COLUMN user_id INTEGER")


# --- Вспомогательные функции ---

def login_required(func):
    """Декоратор для защиты страниц от неавторизованных пользователей."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


# --- Основные маршруты ---

@app.route("/")
@login_required
def index():
    search_query = request.args.get("q", "")
    user_id = session["user_id"]

    # УЯЗВИМОСТЬ 1: SQL-инъекция через конкатенацию строк в поиске
    query = f"SELECT * FROM tickets WHERE user_id = {user_id} AND title LIKE '%{search_query}%'"

    with get_db() as db:
        tickets = db.execute(query).fetchall()

    return render_template("index.html", tickets=tickets, search_query=search_query)


@app.route("/create", methods=["GET", "POST"])
@login_required
def create_ticket():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        category = request.form.get("category", "")
        description = request.form.get("description", "").strip()

        if not title or not category or not description:
            return "Заполните все поля", 400

        with get_db() as db:
            db.execute(
                "INSERT INTO tickets (title, category, description, user_id) VALUES (?, ?, ?, ?)",
                (title, category, description, session["user_id"])
            )

        return redirect(url_for("index"))

    return render_template("create.html")


# --- Аутентификация ---

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return "Заполните все поля", 400

        password_hash = generate_password_hash(password)

        try:
            with get_db() as db:
                db.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, password_hash)
                )
        except sqlite3.IntegrityError:
            return "Такой пользователь уже существует", 400

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))

        return "Неверный логин или пароль", 401

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- Служебные маршруты ---

@app.route("/users")
def users():
    # УЯЗВИМОСТЬ 2: Открытый доступ к логинам и хешам паролей всех пользователей
    with get_db() as db:
        all_users = db.execute("SELECT id, username, password FROM users").fetchall()

    return jsonify([dict(user) for user in all_users])


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
