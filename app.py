from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
import hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key

# --- DB Setup ---
def get_db():
    conn = sqlite3.connect("safegrievance.db")
    conn.row_factory = sqlite3.Row
    return conn

def make_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- Auth ---
def signup(username, password, role):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO users(username,password,role) VALUES(?,?,?)", (username, make_hash(password), role))
    conn.commit()
    conn.close()

def login(username, password):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, make_hash(password)))
    user = c.fetchone()
    conn.close()
    return user

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup_view():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        signup(username, password, role)
        flash('Account created. Please login.')
        return redirect(url_for('login_view'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login_view():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = login(username, password)
        if user:
            session['user'] = dict(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login_view'))
    user = session['user']
    role = user['role']
    if role == 'Citizen':
        return redirect(url_for('citizen_dashboard'))
    elif role == 'Officer':
        return redirect(url_for('officer_dashboard'))
    elif role == 'Municipal':
        return redirect(url_for('municipal_dashboard'))
    elif role == 'Contractor':
        return redirect(url_for('contractor_dashboard'))
    else:
        return "Unknown role"

# --- Citizen Dashboard ---
@app.route('/citizen', methods=['GET', 'POST'])
def citizen_dashboard():
    user = session['user']
    conn = get_db()
    c = conn.cursor()
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['description']
        now = datetime.now().isoformat()
        c.execute("INSERT INTO complaints(citizen_id,title,description,status,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                  (user['id'], title, desc, "Pending", now, now))
        conn.commit()
        flash('Complaint filed!')
    # List complaints
    df = c.execute("SELECT * FROM complaints WHERE citizen_id=?", (user['id'],)).fetchall()
    conn.close()
    return render_template('citizen_dashboard.html', complaints=df)

# --- Officer Dashboard ---
@app.route('/officer', methods=['GET', 'POST'])
def officer_dashboard():
    user = session['user']
    conn = get_db()
    c = conn.cursor()
    complaints = c.execute("SELECT * FROM complaints WHERE officer_id IS NULL OR officer_id=?", (user['id'],)).fetchall()
    if request.method == 'POST':
        action = request.form['action']
        complaint_id = int(request.form['complaint_id'])
        if action == 'assign':
            c.execute("UPDATE complaints SET officer_id=?, status=? WHERE id=?", (user['id'], "In Progress", complaint_id))
        elif action == 'complete':
            contractor = request.form['contractor']
            start = request.form['start']
            end = request.form['end']
            c.execute("UPDATE complaints SET contractor=?, start_date=?, end_date=?, status=? WHERE id=?",
                      (contractor, start, end, "Completed", complaint_id))
        conn.commit()
        return redirect(url_for('officer_dashboard'))
    conn.close()
    return render_template('officer_dashboard.html', complaints=complaints)

# --- Municipal Dashboard ---
@app.route('/municipal', methods=['GET', 'POST'])
def municipal_dashboard():
    conn = get_db()
    c = conn.cursor()
    complaints = c.execute("SELECT * FROM complaints WHERE escalated=1").fetchall()
    if request.method == 'POST':
        action = request.form['action']
        complaint_id = int(request.form['complaint_id'])
        # Actions: verify or false
        if action == 'verify':
            flash("Officer will be punished!")
        elif action == 'false':
            flash("Citizen identity revealed for false complaint!")
        return redirect(url_for('municipal_dashboard'))
    conn.close()
    return render_template('municipal_dashboard.html', complaints=complaints)

# --- Contractor Portal ---
@app.route('/contractor')
def contractor_dashboard():
    conn = get_db()
    c = conn.cursor()
    complaints = c.execute("SELECT * FROM complaints WHERE contractor IS NOT NULL").fetchall()
    conn.close()
    return render_template('contractor_dashboard.html', complaints=complaints)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    # DB Table setup (run once)
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        role TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS complaints(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        citizen_id INTEGER,
        title TEXT,
        description TEXT,
        status TEXT,
        created_at TEXT,
        updated_at TEXT,
        officer_id INTEGER,
        contractor TEXT,
        start_date TEXT,
        end_date TEXT,
        escalated INTEGER DEFAULT 0
    )""")
    conn.commit()
    conn.close()
    app.run(debug=True)