from flask import Flask, render_template, request, redirect, url_for, session, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"
csrf = CSRFProtect(app)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))  # Secure random secret key

DATABASE = 'members.db'

# Store hashed passwords in the USERS dictionary
USERS = {
    "staff": {"password": generate_password_hash("staffpass"), "role": "staff"},
    "member": {"password": generate_password_hash("memberpass"), "role": "member"},
    "pakkarim": {"password": generate_password_hash("karim"), "role": "staff"}
}

# Helper function to connect to the SQLite database
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.before_request
def create_tables():
    db = get_db()
    db.execute('''CREATE TABLE IF NOT EXISTS members (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    membership_status TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS classes (
                    id INTEGER PRIMARY KEY,
                    class_name TEXT NOT NULL,
                    class_time TEXT NOT NULL
                  )''')
    db.execute('''CREATE TABLE IF NOT EXISTS member_classes (
                    member_id INTEGER,
                    class_id INTEGER,
                    FOREIGN KEY (member_id) REFERENCES members (id),
                    FOREIGN KEY (class_id) REFERENCES classes (id)
                  )''')
    db.commit()

# Home Route (Login)
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in USERS and check_password_hash(USERS[username]['password'], password):
            session.clear()  # Prevent session fixation
            session['user'] = username
            session['role'] = USERS[username]['role']
            return redirect(url_for('dashboard'))
        else:
            return "Login Failed!"
    return render_template('login.html')

# Dashboard (for both staff and members)
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    username = session['user']
    return render_template('dashboard.html', username=username)

# Flask-WTF Form for adding members with CSRF protection
class MemberForm(FlaskForm):
    name = StringField('Name')
    status = StringField('Status')
    submit = SubmitField('Add Member')

# Member Management Routes
@app.route('/add_member', methods=['GET', 'POST'])
@csrf.exempt  # CSRF protection for the add_member route
def add_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    form = MemberForm()
    if form.validate_on_submit():
        name = form.name.data
        status = form.status.data
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('add_member.html', form=form)

# View specific member classes
@app.route('/member/<int:member_id>/classes')
def member_classes(member_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    # Use parameterized query to prevent SQL injection
    member = query_db("SELECT * FROM members WHERE id = ?", (member_id,), one=True)
    classes = query_db("SELECT c.class_name, c.class_time FROM classes c "
                        "JOIN member_classes mc ON c.id = mc.class_id "
                        "WHERE mc.member_id = ?", (member_id,))
    
    return render_template('member_classes.html', member=member, classes=classes)

# Register for a class
@app.route('/register_class/<int:member_id>', methods=['GET', 'POST'])
def register_class(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))

    classes = query_db("SELECT * FROM classes")  # Get all available classes
    if request.method == 'POST':
        class_id = request.form['class_id']
        db = get_db()
        db.execute("INSERT INTO member_classes (member_id, class_id) VALUES (?, ?)", (member_id, class_id))
        db.commit()
        return redirect(url_for('member_classes', member_id=member_id))
    
    return render_template('register_class.html', member_id=member_id, classes=classes)

# View all members
@app.route('/view_members')
def view_members():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    members = query_db("SELECT * FROM members")
    return render_template('view_members.html', members=members)

# New Route for Registering a Member
@app.route('/register_member', methods=['GET', 'POST'])
def register_member():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        status = request.form['status']
        db = get_db()
        db.execute("INSERT INTO members (name, membership_status) VALUES (?, ?)", (name, status))
        db.commit()
        return redirect(url_for('view_members'))
    
    return render_template('register_member.html')

# Class Scheduling Routes
@app.route('/add_class', methods=['GET', 'POST'])
def add_class():
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        class_name = request.form['class_name']
        class_time = request.form['class_time']
        db = get_db()
        db.execute("INSERT INTO classes (class_name, class_time) VALUES (?, ?)", (class_name, class_time))
        db.commit()
        return redirect(url_for('view_classes'))
    
    return render_template('add_class.html')

@app.route('/view_classes')
def view_classes():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    classes = query_db("SELECT * FROM classes")
    return render_template('view_classes.html', classes=classes)

# Deleting a member securely
@app.route('/delete_member/<int:member_id>', methods=['POST'])
def delete_member(member_id):
    if 'user' not in session or session['role'] != 'staff':
        return redirect(url_for('login'))
    
    db = get_db()
    db.execute("DELETE FROM members WHERE id = ?", (member_id,))
    db.execute("DELETE FROM member_classes WHERE member_id = ?", (member_id,))
    db.commit()
    
    return redirect(url_for('view_members'))

# Logout Route
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
