from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
import MySQLdb.cursors

app = Flask(__name__)
app.secret_key = 'static_key_for_testing'  # Sementara statis buat tes, ganti random nanti
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'zip', 'doc', 'docx'}
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Max 5MB upload

# Konfigurasi MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  # Kosong untuk default XAMPP
app.config['MYSQL_DB'] = 'qc_security'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Buat folder uploads jika belum ada
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Filter Jinja untuk mengambil nama file dari path
@app.template_filter('basename')
def basename_filter(path):
    return os.path.basename(path)

# Fungsi koneksi database
def get_db():
    return MySQLdb.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        db=app.config['MYSQL_DB'],
        cursorclass=MySQLdb.cursors.DictCursor
    )

# Inisialisasi database
def init_db():
    with get_db() as db:
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) DEFAULT 'user'
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS submissions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                app_name VARCHAR(255) NOT NULL,
                file_path VARCHAR(255) NOT NULL,
                status VARCHAR(50) DEFAULT 'Pending',
                date_submitted DATE NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        db.commit()

# Fungsi untuk cek file yang diizinkan
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Route untuk homepage - SELALU CEK LOGIN
@app.route('/')
def home():
    if 'user_id' not in session:
        print("No user_id in session, redirecting to login")
        return redirect(url_for('login'))
    print(f"User detected, role: {session.get('role')}")
    if session.get('role') == 'admin':
        return redirect(url_for('admin_dashboard'))
    with get_db() as db:
        cursor = db.cursor()
        cursor.execute('SELECT s.*, u.name AS user_name FROM submissions s JOIN users u ON s.user_id = u.id WHERE s.user_id = %s ORDER BY date_submitted DESC',
                       (session['user_id'],))
        submissions = cursor.fetchall()
        pending = sum(1 for s in submissions if s['status'] == 'Pending')
        approved = sum(1 for s in submissions if s['status'] == 'Approved')
        rejected = sum(1 for s in submissions if s['status'] == 'Rejected')
    return render_template('index.html', name=session['name'], submissions=submissions[:5],
                           pending=pending, approved=approved, rejected=rejected)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        with get_db() as db:
            cursor = db.cursor()
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            user = cursor.fetchone()
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['name'] = user['name']
                session['role'] = user['role']
                print(f"Login successful for {email}, role: {session['role']}, user_id: {session['user_id']}")
                flash('Login successful!', 'success')
                if session['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('home'))  # Redirect ke / (index.html) untuk user
            else:
                print(f"Login failed for {email}")
                flash('Invalid email or password.', 'error')
    return render_template('login.html')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('register.html')
        hashed_pw = generate_password_hash(password)
        with get_db() as db:
            cursor = db.cursor()
            try:
                cursor.execute('INSERT INTO users (name, email, password) VALUES (%s, %s, %s)',
                               (name, email, hashed_pw))
                db.commit()
                flash('Registration successful! Please login.', 'success')
                return redirect(url_for('login'))
            except MySQLdb.IntegrityError:
                flash('Email already registered.', 'error')
    return render_template('register.html')

# Dashboard (halaman user)
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        print("No user_id in session, redirecting to login from dashboard")
        return redirect(url_for('login'))
    print(f"Accessing dashboard, role: {session.get('role')}")
    with get_db() as db:
        cursor = db.cursor()
        cursor.execute('SELECT s.*, u.name AS user_name FROM submissions s JOIN users u ON s.user_id = u.id WHERE s.user_id = %s ORDER BY date_submitted DESC',
                       (session['user_id'],))
        submissions = cursor.fetchall()
        pending = sum(1 for s in submissions if s['status'] == 'Pending')
        approved = sum(1 for s in submissions if s['status'] == 'Approved')
        rejected = sum(1 for s in submissions if s['status'] == 'Rejected')
    return render_template('index.html', name=session['name'], submissions=submissions[:5],
                           pending=pending, approved=approved, rejected=rejected)

# Admin Dashboard (halaman admin)
@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session or session['role'] != 'admin':
        print(f"No valid session or not admin, redirecting to login. Session: {session}")
        return redirect(url_for('login'))
    print(f"Accessing admin_dashboard, role: {session.get('role')}")
    with get_db() as db:
        cursor = db.cursor()
        cursor.execute('SELECT s.*, u.name AS user_name FROM submissions s JOIN users u ON s.user_id = u.id ORDER BY s.date_submitted DESC')
        submissions = cursor.fetchall()
        pending = sum(1 for s in submissions if s['status'] == 'Pending')
        approved = sum(1 for s in submissions if s['status'] == 'Approved')
        rejected = sum(1 for s in submissions if s['status'] == 'Rejected')
    return render_template('admin_dashboard.html', name=session['name'], submissions=submissions,
                           pending=pending, approved=approved, rejected=rejected)

# Submissions (halaman untuk upload dan lihat submissions)
@app.route('/submissions', methods=['GET', 'POST'])
def submissions():
    if 'user_id' not in session:
        print("No user_id in session, redirecting to login from submissions")
        return redirect(url_for('login'))
    print(f"Accessing submissions, role: {session.get('role')}")
    if request.method == 'POST':
        app_name = request.form['app_name']
        file = request.files['file']
        if not app_name or not file:
            flash('Application name and file are required!', 'error')
            return redirect(url_for('submissions'))
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            date_submitted = datetime.now().strftime('%Y-%m-%d')
            with get_db() as db:
                cursor = db.cursor()
                cursor.execute('INSERT INTO submissions (user_id, app_name, file_path, date_submitted) VALUES (%s, %s, %s, %s)',
                               (session['user_id'], app_name, file_path, date_submitted))
                db.commit()
            flash('Submission uploaded successfully!', 'success')
            return redirect(url_for('home'))  # Redirect ke / (index.html) setelah upload
        else:
            flash('Invalid file type. Only PDF, ZIP, DOC, DOCX allowed.', 'error')
    # Perubahan di sini: Admin lihat semua submissions, user cuma milik sendiri
    with get_db() as db:
        cursor = db.cursor()
        if session['role'] == 'admin':
            cursor.execute('SELECT s.*, u.name AS user_name FROM submissions s JOIN users u ON s.user_id = u.id ORDER BY s.date_submitted DESC')
        else:
            cursor.execute('SELECT s.*, u.name AS user_name FROM submissions s JOIN users u ON s.user_id = u.id WHERE s.user_id = %s ORDER BY date_submitted DESC',
                           (session['user_id'],))
        subs = cursor.fetchall()
        pending = sum(1 for s in subs if s['status'] == 'Pending')
        approved = sum(1 for s in subs if s['status'] == 'Approved')
        rejected = sum(1 for s in subs if s['status'] == 'Rejected')
    return render_template('submissions.html', submissions=subs,
                           pending=pending, approved=approved, rejected=rejected)

# Action Submission (approve/reject, hanya admin)
@app.route('/action_submission/<int:sub_id>/<action>')
def action_submission(sub_id, action):
    if 'user_id' not in session or session['role'] != 'admin':
        print(f"No valid session or not admin, redirecting to login. Session: {session}")
        flash('Admin access required!', 'error')
        return redirect(url_for('login'))
    if action not in ['approve', 'reject']:
        flash('Invalid action!', 'error')
        return redirect(url_for('admin_dashboard'))
    with get_db() as db:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM submissions WHERE id = %s', (sub_id,))
        sub = cursor.fetchone()
        if sub:
            new_status = 'Approved' if action == 'approve' else 'Rejected'
            cursor.execute('UPDATE submissions SET status = %s WHERE id = %s', (new_status, sub_id))
            db.commit()
            flash(f'Submission {new_status.lower()}!', 'success')
    return redirect(url_for('submissions'))  # Redirect ke /submissions biar data refresh

# Reports (halaman admin review)
@app.route('/reports', methods=['GET', 'POST'])
def reports():
    if 'user_id' not in session or session['role'] != 'admin':
        print(f"No valid session or not admin, redirecting to login. Session: {session}")
        return redirect(url_for('login'))
    print(f"Accessing reports, role: {session.get('role')}")
    with get_db() as db:
        cursor = db.cursor()
        query = 'SELECT s.*, u.name AS user_name FROM submissions s JOIN users u ON s.user_id = u.id ORDER BY s.date_submitted DESC'
        params = ()
        if request.method == 'POST':
            status = request.form.get('status')
            start_date = request.form.get('start_date')
            end_date = request.form.get('end_date')
            conditions = []
            if status and status != 'All':
                conditions.append('s.status = %s')
                params += (status,)
            if start_date:
                conditions.append('s.date_submitted >= %s')
                params += (start_date,)
            if end_date:
                conditions.append('s.date_submitted <= %s')
                params += (end_date,)
            if conditions:
                query += ' WHERE ' + ' AND '.join(conditions)
        cursor.execute(query, params)
        submissions = cursor.fetchall()
    return render_template('reports.html', submissions=submissions, name=session['name'])

# Users (halaman admin manage user)
@app.route('/users', methods=['GET', 'POST'])
def users_page():
    if 'user_id' not in session or session['role'] != 'admin':
        print(f"No valid session or not admin, redirecting to login. Session: {session}")
        return redirect(url_for('login'))
    print(f"Accessing users, role: {session.get('role')}")
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        role = request.form['role']
        password = request.form['password']
        if not name or not email or not role or not password:
            flash('All fields are required!', 'error')
            return redirect(url_for('users_page'))
        if len(password) < 6:
            flash('Password must be at least 6 characters!', 'error')
            return redirect(url_for('users_page'))
        hashed_pw = generate_password_hash(password)
        with get_db() as db:
            cursor = db.cursor()
            try:
                cursor.execute('INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)',
                               (name, email, hashed_pw, role))
                db.commit()
                flash('User added successfully!', 'success')
            except MySQLdb.IntegrityError:
                flash('Email already registered.', 'error')
        return redirect(url_for('users_page'))
    with get_db() as db:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users')
        users = cursor.fetchall()
    return render_template('users.html', users=users)

# Action User
@app.route('/action_user/<int:user_id>/<action>', methods=['GET', 'POST'])
def action_user(user_id, action):
    if 'user_id' not in session or session['role'] != 'admin':
        print(f"No valid session or not admin, redirecting to login. Session: {session}")
        return redirect(url_for('login'))
    with get_db() as db:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('User not found!', 'error')
            return redirect(url_for('users_page'))
        if action == 'delete':
            cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
            db.commit()
            flash('User deleted!', 'success')
            return redirect(url_for('users_page'))
        elif action == 'edit' and request.method == 'POST':
            name = request.form['name']
            email = request.form['email']
            role = request.form['role']
            try:
                cursor.execute('UPDATE users SET name = %s, email = %s, role = %s WHERE id = %s',
                               (name, email, role, user_id))
                db.commit()
                flash('User updated!', 'success')
            except MySQLdb.IntegrityError:
                flash('Email already registered.', 'error')
            return redirect(url_for('users_page'))
        elif action == 'edit':
            cursor.execute('SELECT * FROM users')
            users = cursor.fetchall()
            return render_template('users.html', users=users, edit_user=user)
    return redirect(url_for('users_page'))

# Profile
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        print("No user_id in session, redirecting to login from profile")
        return redirect(url_for('login'))
    print(f"Accessing profile, role: {session.get('role')}")
    with get_db() as db:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
        user = cursor.fetchone()
    if request.method == 'POST':
        if 'save_changes' in request.form:
            name = request.form['name']
            email = request.form['email']
            with get_db() as db:
                cursor = db.cursor()
                try:
                    cursor.execute('UPDATE users SET name = %s, email = %s WHERE id = %s',
                                   (name, email, session['user_id']))
                    db.commit()
                    session['name'] = name
                    flash('Profile updated!', 'success')
                except MySQLdb.IntegrityError:
                    flash('Email already registered.', 'error')
        elif 'change_password' in request.form:
            current_pw = request.form['current_password']
            new_pw = request.form['new_password']
            confirm_pw = request.form['confirm_password']
            if new_pw != confirm_pw:
                flash('Passwords do not match.', 'error')
                return render_template('profile.html', user=user)
            if len(new_pw) < 6:
                flash('New password must be at least 6 characters.', 'error')
                return render_template('profile.html', user=user)
            with get_db() as db:
                cursor = db.cursor()
                cursor.execute('SELECT password FROM users WHERE id = %s', (session['user_id'],))
                user_db = cursor.fetchone()
                if check_password_hash(user_db['password'], current_pw):
                    hashed_new = generate_password_hash(new_pw)
                    cursor.execute('UPDATE users SET password = %s WHERE id = %s',
                                   (hashed_new, session['user_id']))
                    db.commit()
                    flash('Password changed!', 'success')
                else:
                    flash('Current password incorrect.', 'error')
    return render_template('profile.html', user=user)

# Settings
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        print("No user_id in session, redirecting to login from settings")
        return redirect(url_for('login'))
    print(f"Accessing settings, role: {session.get('role')}")
    if request.method == 'POST':
        flash('Settings saved!', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    print("Session cleared, redirecting to login")
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()  # Jalankan sekali, lalu komentari
    app.run(debug=True)