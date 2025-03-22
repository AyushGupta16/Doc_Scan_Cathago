from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash  # Add flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime, date

app = Flask(__name__, 
            static_folder='../frontend/static', 
            template_folder='../frontend/templates')
app.secret_key = 'your-secret-key'  # Replace with a secure key

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database connection
def get_db():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'db.sqlite')
    db = sqlite3.connect(db_path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db

# Initialize database
def init_db():
    with app.app_context():
        db = get_db()
        db.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                credits INTEGER DEFAULT 20,
                last_reset TEXT
            );
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                filename TEXT,
                content TEXT,
                upload_date TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS credit_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                credits_requested INTEGER,
                status TEXT DEFAULT 'pending',
                request_date TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        ''')
        db.commit()
        print("Database initialized successfully.")

# Check and reset credits daily
def reset_credits_if_needed(user_id):
    db = get_db()
    user = db.execute('SELECT credits, last_reset FROM users WHERE id = ?', (user_id,)).fetchone()
    today = date.today().strftime('%Y-%m-%d')
    if user['last_reset'] != today:
        db.execute('UPDATE users SET credits = 20, last_reset = ? WHERE id = ?', (today, user_id))
        db.commit()

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    hashed_password = generate_password_hash(password)
    role = 'admin' if username == 'admin' else 'user'
    try:
        db = get_db()
        db.execute(
            'INSERT INTO users (username, password, role, last_reset) VALUES (?, ?, ?, ?)',
            (username, hashed_password, role, date.today().strftime('%Y-%m-%d'))
        )
        db.commit()
        return jsonify({'message': 'Registration successful'})
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username already exists'}), 400

@app.route('/auth/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if user and check_password_hash(user['password'], password):
        session['user_id'] = user['id']
        session['username'] = user['username']
        session['role'] = user['role']
        reset_credits_if_needed(user['id'])
        return jsonify({'success': True, 'role': user['role']})
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    reset_credits_if_needed(session['user_id'])
    db = get_db()
    user = db.execute('SELECT credits FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return render_template('dashboard.html', credits=user['credits'])

@app.route('/admin')
def admin():
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('index'))
    db = get_db()
    requests = db.execute('SELECT cr.id, u.username, cr.credits_requested, cr.status, cr.request_date '
                          'FROM credit_requests cr JOIN users u ON cr.user_id = u.id '
                          'WHERE cr.status = "pending"').fetchall()
    return render_template('admin.html', requests=requests)

@app.route('/user/profile')
def profile():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401
    reset_credits_if_needed(session['user_id'])
    db = get_db()
    user = db.execute('SELECT username, credits FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return jsonify(dict(user))

@app.route('/scan', methods=['POST'])
def scan():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401
    reset_credits_if_needed(session['user_id'])
    db = get_db()
    user = db.execute('SELECT credits FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if user['credits'] < 1:
        return jsonify({'message': 'Insufficient credits'}), 403
    
    if 'file' not in request.files:
        return jsonify({'message': 'No file uploaded'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    db.execute(
        'INSERT INTO documents (user_id, filename, content, upload_date) VALUES (?, ?, ?, ?)',
        (session['user_id'], filename, content, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    )
    db.execute('UPDATE users SET credits = credits - 1 WHERE id = ?', (session['user_id'],))
    db.commit()
    return jsonify({'message': 'Document scanned successfully'})

@app.route('/credits/request', methods=['POST'])
def request_credits():
    if 'user_id' not in session:
        return jsonify({'message': 'Unauthorized'}), 401
    credits_requested = int(request.form['credits'])
    db = get_db()
    db.execute(
        'INSERT INTO credit_requests (user_id, credits_requested, request_date) VALUES (?, ?, ?)',
        (session['user_id'], credits_requested, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    )
    db.commit()
    return jsonify({'message': 'Credit request submitted'})

@app.route('/admin/approve/<int:request_id>', methods=['POST'])
def approve_credit(request_id):
    if session.get('role') != 'admin':
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'message': 'Unauthorized'}), 401
        return redirect(url_for('index'))
    
    db = get_db()
    req = db.execute('SELECT user_id, credits_requested FROM credit_requests WHERE id = ?', (request_id,)).fetchone()
    if req:
        db.execute('UPDATE users SET credits = credits + ? WHERE id = ?', (req['credits_requested'], req['user_id']))
        db.execute('UPDATE credit_requests SET status = "approved" WHERE id = ?', (request_id,))
        db.commit()
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'message': 'Credit request approved successfully!'})
        flash('Credit request approved successfully!', 'success')
        return redirect(url_for('admin'))
    
    if request.headers.get('Accept') == 'application/json':
        return jsonify({'message': 'Request not found'}), 404
    flash('Request not found.', 'error')
    return redirect(url_for('admin'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)