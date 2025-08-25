from werkzeug.security import generate_password_hash
import MySQLdb.cursors

# Konfigurasi koneksi MySQL (sesuai dengan XAMPP default)
db = MySQLdb.connect(
    host="localhost",
    user="root",
    password="",  # Kosong untuk default XAMPP
    database="qc_security",
    cursorclass=MySQLdb.cursors.DictCursor
)

# Data admin
admin_email = "admin@qcsecurity.com"
admin_password = "admin123"  # Ganti password ini sesuai keinginan
hashed_password = generate_password_hash(admin_password)

# Query untuk insert data
query = "INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)"
values = ("Admin", admin_email, hashed_password, "admin")

# Eksekusi query
cursor = db.cursor()
try:
    cursor.execute(query, values)
    db.commit()
    print("Admin account added successfully!")
except MySQLdb.IntegrityError:
    print("Email already exists or error occurred. Check database.")
finally:
    cursor.close()
    db.close()