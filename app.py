# app.py
from flask import Flask, jsonify, request, session, render_template
from config import db, Config  # Mengimpor db dan Config dari folder config
from models import User  # Mengimpor model User dari config.models
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os

# Inisialisasi aplikasi Flask
app = Flask(__name__)
app.config.from_object(Config)  # Memuat konfigurasi dari file config/config.py

# Menginisialisasi SQLAlchemy
db.init_app(app)

# Fungsi render_dashboard
def render_templates(template_name):
    # Logika kustom untuk merender dashboard
    return render_template(template_name)

# Dekorator Login Required
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Unauthorized access'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return render_templates('index.html')  # Menggunakan render_dashboard untuk merender index.html

# 1. Registrasi User
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], email=data['email'], role=data['role'], password_hash=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# 2. Login User
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()

    if user and check_password_hash(user.password_hash, data['password']):
        session['user_id'] = user.id
        session['username'] = user.username
        return jsonify({'message': 'Login successful'}), 200
    return jsonify({'error': 'Invalid credentials'}), 401

# 3. Dashboard (List User)
@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    users = User.query.all()
    users_list = [{'id': user.id, 'username': user.username, 'email': user.email, 'role': user.role} for user in users]
    return jsonify(users_list), 200

# 4. Tambah User
@app.route('/api/users', methods=['POST'])
@login_required
def add_user():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], email=data['email'], role=data['role'], password_hash=hashed_password)

    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User added successfully'}), 201

# 5. Edit User
@app.route('/api/users/<int:id>', methods=['PUT'])
@login_required
def edit_user(id):
    user = User.query.get_or_404(id)
    data = request.get_json()
    user.username = data['username']
    user.email = data['email']
    user.role = data['role']

    if 'password' in data:
        user.password_hash = generate_password_hash(data['password'], method='sha256')

    db.session.commit()
    return jsonify({'message': 'User updated successfully'}), 200

# 6. Hapus User
@app.route('/api/users/<int:id>', methods=['DELETE'])
@login_required
def delete_user(id):
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'}), 200

# 7. Logout User
@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({'message': 'Logged out successfully'}), 200

# Main Program
if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists('users.db'):
            db.create_all()  # Membuat database dan tabel jika belum ada
    app.run(debug=True)
