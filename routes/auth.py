from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app, Response
from werkzeug.security import generate_password_hash, check_password_hash
import oracledb
import uuid
from datetime import datetime, timedelta
import random

auth = Blueprint("auth", __name__)


def fila_a_dict(cursor, fila):
    """Convierte una fila (tupla) en diccionario usando los nombres de columna"""
    if fila is None:
        return None
    columnas = [col[0].lower() for col in cursor.description]
    return dict(zip(columnas, fila))


@auth.route("/")
def index():
    return render_template("login.html")


@auth.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form["nombre"]
        correo = request.form["correo"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if password != confirm_password:
            flash("Las contraseñas no coinciden", "danger")
            return redirect(url_for("auth.registro"))

        conexion = current_app.get_connection()
        cursor = conexion.cursor()

        # Verificamos si el correo ya existe
        cursor.execute("SELECT ID_USUARIO FROM USUARIO WHERE EMAIL = :email", {"email": correo})
        if cursor.fetchone():
            flash("Ese correo ya está registrado", "danger")
            return redirect(url_for("auth.registro"))

        password_hash = generate_password_hash(password)

        # Insertamos el usuario y recuperamos el ID generado (IDENTITY)
        id_usuario_var = cursor.var(oracledb.NUMBER)
        cursor.execute(
            """INSERT INTO USUARIO (NOMBRE, CONTRA, EMAIL, ESTADO, FECHA_CREACION)
               VALUES (:nombre, :contra, :email, 1, SYSDATE)
               RETURNING ID_USUARIO INTO :id_usuario""",
            {"nombre": nombre, "contra": password_hash, "email": correo, "id_usuario": id_usuario_var}
        )
        id_usuario = int(id_usuario_var.getvalue()[0])

        # Creamos el perfil asociado
        cursor.execute(
            "INSERT INTO PERFIL (ID_USUARIO, NOMBRE) VALUES (:id_usuario, :nombre)",
            {"id_usuario": id_usuario, "nombre": nombre}
        )

        conexion.commit()

        flash("¡Usuario registrado con éxito!", "success")
        return redirect(url_for("auth.index"))

    return render_template("registro.html")


@auth.route("/login", methods=["POST"])
def login():
    correo = request.form["correo"]
    password = request.form["password"]

    conexion = current_app.get_connection()
    cursor = conexion.cursor()
    cursor.execute("SELECT * FROM USUARIO WHERE EMAIL = :email", {"email": correo})
    fila = cursor.fetchone()
    usuario = fila_a_dict(cursor, fila)

    if not usuario or not check_password_hash(usuario["contra"], password):
        flash("Correo o contraseña incorrectos", "danger")
        return redirect(url_for("auth.index"))

    if usuario["estado"] != 1:
        flash("Tu cuenta no está activa", "danger")
        return redirect(url_for("auth.index"))

    # Registramos la sesión en la tabla SESION
    token = str(uuid.uuid4())
    expiracion = datetime.now() + timedelta(hours=8)

    cursor.execute(
        """INSERT INTO SESION (TOKEN, EXPIRACION, IP, DISPOSITIVO, ID_USUARIO)
           VALUES (:token, :expiracion, :ip, :dispositivo, :id_usuario)""",
        {
            "token": token,
            "expiracion": expiracion,
            "ip": request.remote_addr,
            "dispositivo": request.user_agent.string[:100],
            "id_usuario": usuario["id_usuario"]
        }
    )
    conexion.commit()

    session["usuario_id"] = usuario["id_usuario"]
    session["token"] = token

    return redirect(url_for("auth.perfil"))


@auth.route("/perfil", methods=["GET", "POST"])
def perfil():
    if "usuario_id" not in session:
        flash("Debes iniciar sesión primero", "danger")
        return redirect(url_for("auth.index"))

    conexion = current_app.get_connection()
    cursor = conexion.cursor()

    if request.method == "POST":
        foto = request.files.get("foto")

        if foto and foto.filename != "":
            foto_bytes = foto.read()

            cursor.execute(
                "UPDATE PERFIL SET FOTO = :foto WHERE ID_USUARIO = :id_usuario",
                {"foto": foto_bytes, "id_usuario": session["usuario_id"]}
            )
            conexion.commit()
            flash("Foto actualizada correctamente", "success")

        return redirect(url_for("auth.perfil"))

    cursor.execute(
        """SELECT U.NOMBRE, U.EMAIL, U.FECHA_CREACION, P.NOMBRE AS NOMBRE_PERFIL
           FROM USUARIO U
           LEFT JOIN PERFIL P ON P.ID_USUARIO = U.ID_USUARIO
           WHERE U.ID_USUARIO = :id_usuario""",
        {"id_usuario": session["usuario_id"]}
    )
    fila = cursor.fetchone()
    usuario = fila_a_dict(cursor, fila)

    return render_template("perfil.html", usuario=usuario)


@auth.route("/logout")
def logout():
    if "token" in session:
        conexion = current_app.get_connection()
        cursor = conexion.cursor()
        cursor.execute("DELETE FROM SESION WHERE TOKEN = :token", {"token": session["token"]})
        conexion.commit()

    session.clear()
    flash("Sesión cerrada", "success")
    return redirect(url_for("auth.index"))


@auth.route("/perfil/foto")
def foto_perfil():
    if "usuario_id" not in session:
        return redirect(url_for("auth.index"))

    conexion = current_app.get_connection()
    cursor = conexion.cursor()

    cursor.execute(
        "SELECT FOTO FROM PERFIL WHERE ID_USUARIO = :id_usuario",
        {"id_usuario": session["usuario_id"]}
    )
    fila = cursor.fetchone()

    if fila and fila[0] is not None:
        imagen_bytes = fila[0].read()
        return Response(imagen_bytes, mimetype="image/jpeg")

    return current_app.send_static_file("fotos/default.jpeg")


@auth.route("/prueba")
def prueba():
    cursor = current_app.get_connection().cursor()
    cursor.execute("SELECT COUNT(*) FROM USUARIO")
    usuarios = cursor.fetchone()[0]

    return f"Usuarios: {usuarios}"