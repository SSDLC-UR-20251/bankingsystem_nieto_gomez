from _datetime import datetime
import time
from app.validation import *
from app.reading import *
from flask import request, jsonify, redirect, url_for, render_template, session, make_response
from app import app

app.secret_key = 'your_secret_key'


MAX_ATTEMPTS = 3                # Número máximo de intentos permitidos
BLOCK_TIME = 5 * 60             # Tiempo de bloqueo en segundos (5 minutos)
user_states = {}                # Diccionario para registrar el estado de los usuarios

def authenticate_user(email, password, db):
    email = normalize_input(email)

    # Inicializa el estado del usuario si no existe
    if email not in user_states:
        user_states[email] = {"intentos": 0, "tiempoBloqueo": 0}

    current_time = time.time()
    # Verificar si la cuenta está bloqueada
    if user_states[email]["tiempoBloqueo"] > current_time:
        remaining_time = user_states[email]["tiempoBloqueo"] - current_time
        minutes = int(remaining_time // 60)
        seconds = int(remaining_time % 60)
        return False, f"Cuenta bloqueada. Intenta de nuevo en {minutes} min {seconds} s."

    # Si el bloqueo expiró, restablecer los contadores
    if user_states[email]["tiempoBloqueo"] and user_states[email]["tiempoBloqueo"] <= current_time:
        user_states[email]["intentos"] = 0
        user_states[email]["tiempoBloqueo"] = 0

    # Verificar si el correo existe en la base de datos
    if email not in db:
        return False, "Usuario no existe en la base de datos."

    # Verificar la contraseña
    if db[email]["password"] == password:
        # Contraseña correcta: se resetea el contador de intentos fallidos
        user_states[email]["intentos"] = 0
        return True, "Autenticación exitosa."
    else:
        # Contraseña incorrecta: incrementar contador de intentos
        user_states[email]["intentos"] += 1
        attempts_left = MAX_ATTEMPTS - user_states[email]["intentos"]
        if user_states[email]["intentos"] >= MAX_ATTEMPTS:
            user_states[email]["tiempoBloqueo"] = current_time + BLOCK_TIME
            return False, "Has superado el número de intentos. La cuenta se bloquea durante 5 minutos."
        else:
            return False, f"Contraseña incorrecta. Intentos restantes: {attempts_left}."


@app.route('/api/users', methods=['POST'])
def create_record():
    data = request.form
    email = data.get('email')
    username = data.get('username')
    nombre = data.get('nombre')
    apellido = data.get('Apellidos')
    password = data.get('password')
    dni = data.get('dni')
    dob = data.get('dob')
    errores = []
    print(data)
    # Validaciones
    if not validate_email(email):
        errores.append("Email inválido")
    if not validate_pswd(password):
        errores.append("Contraseña inválida")
    if not validate_dob(dob):
        errores.append("Fecha de nacimiento inválida")
    if not validate_dni(dni):
        errores.append("DNI inválido")
    if not validate_user(username):
        errores.append("Usuario inválido")
    if not validate_name(nombre):
        errores.append("Nombre inválido")
    if not validate_name(apellido):
        errores.append("Apellido inválido")

    if errores:
        return render_template('form.html', error=errores)

    # Normalizamos email y password
    email = normalize_input(email)
    password = normalize_input(password)

    db = read_db("db.txt")
    db[email] = {
        'nombre': normalize_input(nombre),
        'apellido': normalize_input(apellido),
        'username': normalize_input(username),
        'password': password,  # ya normalizado
        "dni": dni,
        'dob': normalize_input(dob),
        "role": "admin"  # Ajusta el rol según convenga
    }

    write_db("db.txt", db)
    return redirect("/login")


# Endpoint para el login
@app.route('/api/login', methods=['POST'])
def api_login():
    email = normalize_input(request.form['email'])
    password = normalize_input(request.form['password'])
    db = read_db("db.txt")

    # Llamada a la función de autenticación con bloqueo
    auth_success, message = authenticate_user(email, password, db)
    if not auth_success:
        return render_template('login.html', error=message)

    # Si la autenticación es exitosa, se establece el rol y el email en la sesión
    session['role'] = db[email].get('role', 'user')
    session['email'] = email
    return redirect(url_for('customer_menu'))


# Página principal del menú del cliente
@app.route('/customer_menu')
def customer_menu():
    db = read_db("db.txt")
    transactions = read_db("transaction.txt")
    current_balance = 100
    last_transactions = []
    message = request.args.get('message', '')
    error = request.args.get('error', 'false').lower() == 'true'
    return render_template('customer_menu.html',
                           message=message,
                           nombre="",
                           balance=current_balance,
                           last_transactions=last_transactions,
                           error=error,)


# Endpoint para leer un registro
@app.route('/records', methods=['GET'])
def read_record():
    db = read_db("db.txt")
    message = request.args.get('message', '')
    role = session.get('role')

    if role == 'admin':
        users = db
    elif role == 'user':
        user_email = session.get('email')
        users = {user_email: db[user_email]} if user_email in db else {}
    else:
        users = {}

    return render_template('records.html', users=users, role=role, message=message)


@app.route('/update_user/<email>', methods=['POST'])
def update_user(email):
    if session.get('role') == 'user' and session.get('email') != email:
        return redirect(url_for('read_record', message="No tiene permiso para modificar este registro"))

    db = read_db("db.txt")
    username = request.form['username']
    dni = request.form['dni']
    dob = request.form['dob']
    nombre = request.form['nombre']
    apellido = request.form['apellido']
    errores = []

    if not validate_dob(dob):
        errores.append("Fecha de nacimiento inválida")
    if not validate_dni(dni):
        errores.append("DNI inválido")
    if not validate_user(username):
        errores.append("Usuario inválido")
    if not validate_name(nombre):
        errores.append("Nombre inválido")
    if not validate_name(apellido):
        errores.append("Apellido inválido")

    if errores:
        return render_template('edit_user.html',
                               user_data=db[email],
                               email=email,
                               error=errores)

    db[email]['username'] = normalize_input(username)
    db[email]['nombre'] = normalize_input(nombre)
    db[email]['apellido'] = normalize_input(apellido)
    db[email]['dni'] = dni
    db[email]['dob'] = normalize_input(dob)

    write_db("db.txt", db)
    return redirect(url_for('read_record', message="Información actualizada correctamente"))

@app.route('/delete_user/<email>', methods=['POST'])
def delete_user(email):
    if session.get('role') != 'admin':
        return redirect(url_for('read_record', message="No tiene permiso para eliminar usuarios"))
    
    db = read_db("db.txt")
    if email in db:
        del db[email]
        write_db("db.txt", db)
        return redirect(url_for('read_record', message="Usuario eliminado correctamente"))
    else:
        return redirect(url_for('read_record', message="El usuario no existe"))
