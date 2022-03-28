
from flask.views import MethodView
from flask import jsonify, request, session
#from model import users
import hashlib
import pymysql
import bcrypt
import jwt
from config import KEY_TOKEN_AUTH
import datetime
from validators import CreateRegisterSchema
from validators import CreateLoginSchema
from validators import CreateProductoSchema


def crear_conexion():
    try:
        #conexion a la db
        conexion = pymysql.connect(host='localhost',user='root',passwd='',db="Almacen" )
        return conexion
    except pymysql.Error as error:
        print('Se ha producido un error al crear la conexión:', error)


create_register_schema = CreateRegisterSchema()
create_login_schema = CreateLoginSchema()
#create_compra_schema = CreateCompraSchema()
create_crearproducto_schema =CreateProductoSchema()

#http://127.0.0.1:5000/register
class RegisterControllers(MethodView):
    """
        register
    """
    def post(self):
        content = request.get_json()
        email = content.get("email")# =diemaur_0527@yahoo.com
        nombres = content.get("nombres")# = Diego Mauricio
        apellidos = content.get("apellidos") # = Alzate Enciso
        password = content.get("password") # = 123456789
        print("--------", email, nombres, apellidos,password)
        salt = bcrypt.gensalt() ## son para hacer hash
        hash_password = bcrypt.hashpw(bytes(str(password), encoding= 'utf-8'), salt)## son para hacer hash
        errors = create_register_schema.validate(content)
        if errors:
            return errors, 400
        conexion=crear_conexion()
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT password,correo FROM registro WHERE correo=%s", (email, ))
        auto=cursor.fetchone()
        if auto==None:
            cursor.execute(
                 "INSERT INTO registro (correo,nombres,apellidos,password) VALUES(%s,%s,%s,%s)", (email,nombres,apellidos,hash_password,))
            conexion.commit()
            conexion.close()
            return ("bienvenido registro exitoso")
        else :    
            conexion.commit()
            conexion.close()
            return ("el usuario ya esta registrado")

#http://127.0.0.1:5000/login?email=diemaur_0527@yahoo.com&password=123456789
class LoginControllers(MethodView):
    """
        Login
    """
    def post(self):
        content= request.get_json()
        password = content.get("password")
        email = content.get("email")
        create_login_schema = CreateLoginSchema()
        errors = create_login_schema.validate(content)
        if errors:
            return errors, 400
        salt = bcrypt.gensalt()
        user_password= bcrypt.hashpw(bytes(str(password), encoding= 'utf-8'), salt)
        conexion=crear_conexion()
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT password,correo,nombres FROM registro WHERE correo=%s", (email, )
        )
        auto = cursor.fetchone()
        conexion.close()

        if auto==None:
            return jsonify({"Status": "usuario no registrado 22"}), 400

        db_password = bytes(auto[0], encoding="utf-8")

        if (auto[1]==email):
            if not bcrypt.checkpw(user_password, db_password):
                encoded_jwt = jwt.encode({'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=3000), 'email': email}, KEY_TOKEN_AUTH , algorithm='HS256')
                return jsonify({"Status": "login exitoso","usuario: "+auto[2]+ "token ": encoded_jwt}), 200
        else:
            return jsonify({"Status": "correo o clave incorrecta"}), 400


class CreateProductoControllers(MethodView):
    """
        create
    """
    def post(self):
        content = request.get_json()
        nombrep = content.get("nombre")# = Mouse usb
        precio = content.get("precio") # = 12000
        print("--------", nombrep, precio)
        print(content)
       # errors = create_crearproducto_schema.validate(content)
        #if errors:
         #   return errors, 400
        conexion=crear_conexion()
        cursor = conexion.cursor()
        cursor.execute(
                 "INSERT INTO productos (nombreproducto,precio) VALUES(%s,%s)", (nombrep,precio))
        conexion.commit()
        conexion.close()
        return ("Nuevo producto creado satisfactoriamente")
        

#http://127.0.0.1:5000/comprar

# {
#   "idproducto": 1
# }

# class ComprarControllers(MethodView):
#     def post(self):
#         content = request.get_json()
#         idp = content.get("idproducto")
#         #Parametros por cabecera
#         try:
#             if (request.headers.get('Authorization')):
#                 token = request.headers.get("Authorization").split(" ")
#                 decoded_jwt = jwt.decode(token[1], KEY_TOKEN_AUTH , algorithms=['HS256'])
#                 #validaciones
#                 print("-----correo:",decoded_jwt.get("email")) 
#                 errors = create_compra_schema.validate(content)
#                 if errors:
#                     return errors, 400
#                 ###consulta base de datos
#                 conexion=crear_conexion()
#                 cursor = conexion.cursor()
#                 cursor.execute("SELECT nom_producto, precio FROM producto WHERE cod_producto=%s", (idp, ) )
#                 auto1 = cursor.fetchone()
#                 print(auto1)
#                 return jsonify({"Status": "Autorizado por token", "emailExtraido": decoded_jwt.get("email")}), 200
#             else:
#                 return jsonify({"Status": "Token invalido"}), 400
#         except:
#             return jsonify({"Status": "No ha enviado un token"}), 403

#http://127.0.0.1:5000/productos
class ProductosControllers(MethodView):
    """
        json
    """
    def get(self):
        #consulta base de datos
        conexion=crear_conexion()
        cursor = conexion.cursor()
        cursor.execute(
            "SELECT * FROM productos")
        auto=cursor.fetchall()
        conexion.commit()
        conexion.close()
        return jsonify(auto), 200
