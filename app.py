from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'supersecretkey'

# ----- DATABASE SETUP -----
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    is_admin INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS reservations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    train TEXT NOT NULL,
                    date TEXT NOT NULL,
                    user_id INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

init_db()

# ----- ROUTES -----
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already taken."
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT id, password, is_admin FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password_input):
            session['user_id'] = user[0]
            session['is_admin'] = bool(user[2])
            return redirect(url_for('dashboard' if user[2] else 'index'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/reserve', methods=['POST'])
def reserve():
    if 'user_id' not in session:
        return jsonify({'status': 'error', 'message': 'Please login first.'}), 403

    data = request.json
    name = data['name']
    train = data['train']
    date = data['date']
    user_id = session['user_id']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO reservations (name, train, date, user_id) VALUES (?, ?, ?, ?)",
              (name, train, date, user_id))
    conn.commit()
    conn.close()

    return jsonify({'status': 'success', 'message': f'Reservation confirmed for {name} on train {train} for {date}.'})

@app.route('/dashboard')
def dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT r.name, r.train, r.date, u.username
                 FROM reservations r
                 JOIN users u ON r.user_id = u.id''')
    reservations = c.fetchall()
    conn.close()
    return render_template('dashboard.html', reservations=reservations)
