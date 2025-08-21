import os
import sqlite3
from flask import Flask, request, redirect, url_for, render_template_string, session, flash
from werkzeug.utils import secure_filename
import json
import hashlib  # Untuk hashing password sederhana (ganti ke bcrypt kalau mau lebih secure)

app = Flask(__name__)
app.secret_key = 'super_secret_key'  # Ganti ini dengan key random untuk production
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx'}  # Batasi tipe file

# Fungsi cek extension file
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Init DB (jalankan sekali manual atau otomatis)
def init_db():
    conn = sqlite3.connect('qc.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT NOT NULL,
                 password TEXT NOT NULL,
                 role TEXT DEFAULT 'user'
                 )''')
    c.execute('''CREATE TABLE IF NOT EXISTS submissions (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER NOT NULL,
                 description TEXT,
                 files TEXT,  -- JSON of file paths
                 status TEXT DEFAULT 'pending',
                 comments TEXT,
                 FOREIGN KEY (user_id) REFERENCES users(id)
                 )''')
    # Insert contoh user (password hashed)
    hashed_pass_user = hashlib.sha256('password123'.encode()).hexdigest()
    hashed_pass_admin = hashlib.sha256('admin123'.encode()).hexdigest()
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('user1', ?, 'user')", (hashed_pass_user,))
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', ?, 'admin')", (hashed_pass_admin,))
    conn.commit()
    conn.close()

init_db()  # Jalankan init DB pertama kali

# Fungsi DB connection
def get_db():
    conn = sqlite3.connect('qc.db')
    conn.row_factory = sqlite3.Row  # Biar return dict-like
    return conn

# Route Login
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Login gagal!')
    return render_template_string('''
    <!DOCTYPE html>
    <html><head><title>Login</title></head><body>
    <form method="POST">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    {{ get_flashed_messages() }}
    </body></html>
    ''')

# Route User Dashboard (Upload)
@app.route('/user_dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if 'user_id' not in session or session['role'] != 'user':
        return redirect(url_for('login'))
    if request.method == 'POST':
        description = request.form['description']
        file_paths = []
        if 'files' not in request.files:
            flash('No file part')
            return redirect(request.url)
        files = request.files.getlist('files')
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                file_paths.append(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        if file_paths:
            conn = get_db()
            c = conn.cursor()
            files_json = json.dumps(file_paths)
            c.execute("INSERT INTO submissions (user_id, description, files) VALUES (?, ?, ?)",
                      (session['user_id'], description, files_json))
            conn.commit()
            conn.close()
            flash('Upload berhasil! Menunggu approval.')
        else:
            flash('Gagal upload.')
    return render_template_string('''
    <!DOCTYPE html>
    <html><head><title>User Dashboard</title></head><body>
    <h2>Upload Bukti QC</h2>
    <form method="POST" enctype="multipart/form-data">
        Deskripsi: <textarea name="description"></textarea><br>
        Files (multiple): <input type="file" name="files" multiple><br>
        <input type="submit" value="Submit">
    </form>
    {{ get_flashed_messages() }}
    </body></html>
    ''')

# Route Admin Dashboard (Review)
@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT s.id, u.username, s.description, s.files, s.status FROM submissions s JOIN users u ON s.user_id = u.id WHERE s.status = 'pending'")
    submissions = c.fetchall()
    conn.close()
    
    html = '''
    <!DOCTYPE html>
    <html><head><title>Admin Dashboard</title></head><body>
    <h2>Pending Submissions</h2>
    <table border="1">
        <tr><th>ID</th><th>User</th><th>Deskripsi</th><th>Files</th><th>Action</th></tr>
    '''
    for sub in submissions:
        files = json.loads(sub['files'])
        files_links = '<br>'.join([f'<a href="/{file}" target="_blank">View {os.path.basename(file)}</a>' for file in files])
        html += f'''
        <tr>
            <td>{sub['id']}</td>
            <td>{sub['username']}</td>
            <td>{sub['description']}</td>
            <td>{files_links}</td>
            <td>
                <form method="POST" action="/approve/{sub['id']}">
                    <textarea name="comments" placeholder="Komentar"></textarea><br>
                    <input type="submit" name="action" value="Approve">
                    <input type="submit" name="action" value="Reject">
                </form>
            </td>
        </tr>
        '''
    html += '</table></body></html>'
    return render_template_string(html)

# Route Approve/Reject
@app.route('/approve/<int:sub_id>', methods=['POST'])
def approve(sub_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))
    comments = request.form['comments']
    action = request.form['action']
    status = 'approved' if action == 'Approve' else 'rejected'
    conn = get_db()
    c = conn.cursor()
    c.execute("UPDATE submissions SET status = ?, comments = ? WHERE id = ?", (status, comments, sub_id))
    conn.commit()
    conn.close()
    flash('Update berhasil!')
    return redirect(url_for('admin_dashboard'))

# Route Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Serve uploaded files
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)