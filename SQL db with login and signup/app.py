import os
from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Secret key for session management
app.secret_key = os.getenv('SECRET_KEY')

# MySQL configuration using environment variables
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST')
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB')

mysql = MySQL(app)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Fetch user from database
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()

        if user and check_password_hash(user[3], password):  # user[3] is the hashed password in DB
            session['user_id'] = user[0]
            flash('Login successful', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Password validation
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        created_at = datetime.now()

        # Insert into MySQL
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users (name, email, password, registration_date) VALUES (%s, %s, %s, %s)",
                       (name, email, hashed_password, created_at))
        mysql.connection.commit()
        cursor.close()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return 'Welcome to your dashboard!'

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
