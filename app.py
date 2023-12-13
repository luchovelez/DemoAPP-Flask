from flask import Flask, render_template, redirect, url_for, session, json
from wtforms import PasswordField
from wtforms.validators import InputRequired, Email, Length
import firebase_admin
import csv
from firebase_admin import credentials, auth
import jwt
import datetime
from functools import wraps
from flask import request, jsonify
from flask_wtf import FlaskForm
from wtforms import FileField, StringField, SubmitField
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from wtforms.validators import DataRequired
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Verifica si el token está en los encabezados de la solicitud
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # Decodifica el token
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = auth.get_user(data['sub'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated
def generate_token(user_id):
    try:
        # Genera un token JWT con una duración de 1 día
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            flask_secret_key,  # Usa la misma clave secreta que para la sesión
            algorithm='HS256'
        )
    except Exception as e:
        return str(e)

# Carga la configuración de Firebase Admin SDK desde el archivo credentials.json
cred = credentials.Certificate("Credentials/credentials.json")
firebase_admin.initialize_app(cred)

# Abre el archivo de credenciales JSON
with open("Credentials/credentials.json") as json_file:
    cred_data = json.load(json_file)

# Accede a la clave secreta del archivo de credenciales
flask_secret_key = cred_data.get("flask_secret_key")
smtp_username = cred_data.get("smtp_username")
smtp_password = cred_data.get("smtp_password")
jwt_secret_key = cred_data.get("jwt_secret_key")

# Crea la aplicación Flask y configura la clave secreta
app = Flask(__name__)
app.secret_key = flask_secret_key
app.config['JWT_SECRET_KEY'] = jwt_secret_key
jwt = JWTManager(app)

class LoginForm(FlaskForm):
    email = StringField('Correo Electrónico', validators=[InputRequired(), Email(), Length(max=100)])
    password = PasswordField('Contraseña', validators=[InputRequired(), Length(min=8, max=100)])
    submit = SubmitField('Iniciar sesión')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        print(request.form)  # Imprimir los datos del formulario

        # Acceder a los datos del formulario solo si el método es POST
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            # Crea el usuario en Firebase Authentication
            user = auth.create_user(email=email, password=password)
            print(f"Usuario creado: {user.uid}")
            return render_template('login.html')

        except Exception as e:
            print(f"Error al crear usuario: {str(e)}")
            # Maneja el error según tus necesidades
            return "Error al crear usuario"
    else:
        # Si el método no es POST, simplemente renderiza la página de registro
        return render_template('registro.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['correo']
        password = request.form['password']
        # Verifica las credenciales aquí (por ejemplo, con Firebase Authentication)

        try:
            # Obtén el usuario por su correo electrónico
            user = auth.get_user_by_email(email)

            # Verifica la contraseña aquí si es necesario
            # Puedes comparar la contraseña proporcionada con la almacenada en la base de datos

            # Si la autenticación es exitosa, 'user' contendrá información sobre el usuario autenticado
            # Almacena la información del usuario en la sesión
            session['user_id'] = user.uid
            # Si las credenciales son válidas, crea un token JWT
            access_token = create_access_token(identity=email)
            print(access_token)
            return render_template('welcome.html')


        except auth.AuthError as e:
            print(f'Error de inicio de sesión: {str(e)}')
            # Maneja el error según tus necesidades, proporcionando mensajes de error más detallados
            return "Error de inicio de sesión"

    return render_template('login.html')


@app.route('/bienvenida')
def bienvenida():
    # Renderiza la página de bienvenida o realiza acciones adicionales
    return render_template('welcome.html')


@app.route('/logout')
def logout():
    # Cierre de sesión de Firebase (elimina la sesión del usuario)
    session.clear()

    # Redirige al usuario a la página de inicio
    return redirect(url_for('index'))


# Ruta para obtener la lista de todos los Pokémon desde el archivo CSV
@jwt_required()
@app.route('/api/pokemons', methods=['GET'])
def get_pokemons():
    pokemons = []
    try:
        with open('pokemon.csv', newline='') as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                pokemons.append({
                    'id': int(row['id']),
                    'name': row['name'],
                    'type': row['type']
                })
        return jsonify(pokemons)

    except FileNotFoundError:
        return jsonify({"error": "Archivo Pokémon no encontrado"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Ruta para obtener información de un Pokémon específico por ID desde el archivo CSV
@jwt_required()
@app.route('/api/pokemon/<int:pokemon_id>', methods=['GET'])
def get_pokemonId(pokemon_id):
    try:
        with open('API/pokemon.csv', newline='') as csvfile:
            csvreader = csv.DictReader(csvfile)
            for row in csvreader:
                if int(row['id']) == pokemon_id:
                    return jsonify({
                        'id': int(row['id']),
                        'name': row['name'],
                        'type': row['type']
                    })
        return jsonify({"error": "Pokémon no encontrado"}), 404

    except FileNotFoundError:
        return jsonify({"error": "Archivo Pokémon no encontrado"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500# Ruta para obtener información de un Pokémon específico por ID desde el archivo CSV

# Ruta para obtener información de todos los Pokémon desde el archivo CSV
@jwt_required()
@app.route('/api/get_pokemon', methods=['GET'])
def get_pokemones():
    try:
        # Abre el archivo CSV
        with open('API/pokemon.csv', newline='') as csvfile:
            csvreader = csv.DictReader(csvfile)
            pokemons = [row for row in csvreader]

        # Obtiene parámetros de consulta de la URL
        parametros = request.args

        # Filtra los Pokémon según los parámetros proporcionados
        resultado = []
        for pokemon in pokemons:
            match = True
            for key, value in parametros.items():
                if pokemon.get(key, '').lower() != value.lower():
                    match = False
                    break
            if match:
                resultado.append(pokemon)

        if not resultado:
            return jsonify({"error": "No se encontraron Pokémon que coincidan con los parámetros"}), 404

        return jsonify(resultado)

    except FileNotFoundError:
        return jsonify({"error": "Archivo Pokémon no encontrado"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

class UploadForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    file = FileField('Archivo', validators=[DataRequired()])
    submit = SubmitField('Enviar')

def enviarEmail(receiver_address, file):
    # Configuración del servidor de correo y envío del email
    sender_address = smtp_username
    sender_pass = smtp_password

    # Configuración del mensaje
    message = MIMEMultipart()
    message['From'] = sender_address
    message['To'] = receiver_address
    message['Subject'] = 'Archivo Enviado desde AppDashboards'

    # Adjuntar el archivo
    part = MIMEBase('application', "octet-stream")
    part.set_payload(file.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', 'attachment; filename="%s"' % file.filename)
    message.attach(part)

    # Crear la sesión y enviar el email
    session = smtplib.SMTP('smtp.gmail.com', 587)  # Usar 465 para SSL
    session.starttls()  # Habilitar seguridad
    session.login(sender_address, sender_pass)  # Iniciar sesión en el servidor
    text = message.as_string()
    session.sendmail(sender_address, receiver_address, text)
    session.quit()

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        email = form.email.data
        file = form.file.data
        enviarEmail(email, file)
        return 'Correo enviado con éxito a %s' % email
    return render_template('upload.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)
