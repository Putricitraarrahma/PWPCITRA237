from flask import Flask, render_template, redirect, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disarankan untuk menonaktifkan modifikasi pelacakan
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    role = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

# Initialize database
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validasi input
        if password != confirm_password:
            flash('Password tidak sesuai.', 'danger')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password harus 6 atau lebih karakter.', 'danger')
            return render_template('register.html')
        
        # Cek apakah username atau email sudah ada
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another one.', 'danger')
            return render_template('register.html')
        
        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email already exists. Please use another email.', 'danger')
            return render_template('register.html')

        # Hash password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, role=role, password_hash=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User registered successfully!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()  # Rollback jika ada error
            flash(f'Error occurred: {str(e)}', 'danger')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        try:
            if user and bcrypt.check_password_hash(user.password_hash, password):
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))  # Langsung menuju dashboard tanpa sesi
            else:
                flash('Username or Password is incorrect.', 'danger')  # Pesan error yang lebih jelas
        except Exception as e:
            flash(f"An error occurred during login: {str(e)}", 'danger')
            print(f"Error: {e}")  # Log the error for debugging

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    # Tampilkan dashboard hanya jika ada pengguna yang login
    # Anda bisa menambahkan session check jika diperlukan
    users = User.query.all()
    return render_template('dashboard.html', users=users)


@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        password = request.form['password']

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, role=role, password_hash=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('User added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()  # Rollback jika ada error
            flash(f'Error occurred: {str(e)}', 'danger')

    return render_template('add_user.html')


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        # Ambil data dari form
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        password = request.form['password']

        # Jika password diubah, hash password baru
        if password:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user.password_hash = hashed_password

        # Perbarui data pengguna
        user.username = username
        user.email = email
        user.role = role
        
        try:
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error occurred: {str(e)}', 'danger')

    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['GET'])
def delete_user(user_id):
    user = User.query.get_or_404(user_id)

    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        db.session.rollback()
        flash(f'Error occurred: {str(e)}', 'danger')
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

# Error handling for 404 - Page Not Found
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Running the app in debug mode
if __name__ == "__main__":
    app.run(debug=True)
