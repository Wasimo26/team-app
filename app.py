# app.py

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# App-Konfiguration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dies-ist-ein-sehr-geheimer-schluessel'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Datenbank-Modelle ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    done = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# ÄNDERUNG: user_id wurde hier entfernt, damit Notizen für alle gelten
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)

class CalendarEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    start = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Webseiten-Routen ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Login fehlgeschlagen. Überprüfe Benutzername und Passwort.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    # ÄNDERUNG: Lädt ALLE Notizen, nicht nur die des Benutzers
    notes = Note.query.all()
    events = CalendarEvent.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', name=current_user.username, tasks=tasks, notes=notes, events=events)

# --- Checklisten-Routen (unverändert) ---
@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    new_task = Task(content=request.form['content'], user_id=current_user.id)
    db.session.add(new_task)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/toggle_task/<int:id>')
@login_required
def toggle_task(id):
    task = Task.query.get(id)
    if task and task.user_id == current_user.id:
        task.done = not task.done
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete_task/<int:id>')
@login_required
def delete_task(id):
    task = Task.query.get(id)
    if task and task.user_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('index'))

# --- Notizen-Routen (angepasst) ---
@app.route('/add_note', methods=['POST'])
@login_required
def add_note():
    # ÄNDERUNG: user_id wird nicht mehr gebraucht
    new_note = Note(content=request.form['content'])
    db.session.add(new_note)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete_note/<int:id>')
@login_required
def delete_note(id):
    note = Note.query.get(id)
    # ÄNDERUNG: Jeder eingeloggte Benutzer kann jede Notiz löschen
    if note:
        db.session.delete(note)
        db.session.commit()
    return redirect(url_for('index'))

# --- Kalender-Routen (unverändert) ---
@app.route('/add_event', methods=['POST'])
@login_required
def add_event():
    new_event = CalendarEvent(title=request.form['title'], start=request.form['start'], user_id=current_user.id)
    db.session.add(new_event)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete_event/<int:id>')
@login_required
def delete_event(id):
    event = CalendarEvent.query.get(id)
    if event and event.user_id == current_user.id:
        db.session.delete(event)
        db.session.commit()
    return redirect(url_for('index'))


def setup_database(app):
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='Wasim').first():
            hashed_password = generate_password_hash('passwort123', method='pbkdf2:sha256')
            new_user = User(username='Wasim', password=hashed_password)
            db.session.add(new_user)
        if not User.query.filter_by(username='Jan').first():
            hashed_password = generate_password_hash('janpasswort', method='pbkdf2:sha256')
            new_user = User(username='Jan', password=hashed_password)
            db.session.add(new_user)
        if not User.query.filter_by(username='Achim').first():
            hashed_password = generate_password_hash('geheim456', method='pbkdf2:sha256')
            new_user = User(username='Achim', password=hashed_password)
            db.session.add(new_user)
        db.session.commit()

if __name__ == '__main__':
    setup_database(app)
    app.run(debug=True)