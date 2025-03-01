from flask import render_template, request, redirect, url_for, session
from app import app
from app.reading import read_db, write_db
from app.encryption import hash_with_salt, verify_password

db_file = "db.txt"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        
        db = read_db(db_file)
        
        if email in db:
            return "Usuario ya registrado"
        
        hashed_password, salt = hash_with_salt(password)
        db[email] = {"password": hashed_password, "salt": salt}
        write_db(db_file, db)
        
        return redirect(url_for("login"))
    
    return render_template('form.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        
        db = read_db(db_file)
        
        if email not in db:
            return "Credenciales inválidas"
        
        stored_hash = db[email]["password"]
        stored_salt = db[email]["salt"]
        
        if verify_password(stored_hash, stored_salt, password):
            session['user'] = email
            return "Inicio de sesión exitoso"
        else:
            return "Credenciales inválidas"
    
    return render_template("login.html")
