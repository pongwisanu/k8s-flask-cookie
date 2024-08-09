from flask import Flask , jsonify , request , render_template
from flask_jwt_extended import JWTManager , create_access_token , get_jwt_identity , jwt_required , set_access_cookies , unset_jwt_cookies , get_jwt
from redis import Redis

import os
import socket
import secrets

app = Flask(__name__)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False
# app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")
app.config['JWT_SECRET_KEY']  = "e8fe0e7be2ce126db030969c79f0de3e014fc16b07b6ae7b7d4f52d7478689b5"

jwt = JWTManager(app)

client = Redis(host="redis-service", port=6379 , db=0)

@app.route("/login" , methods=["POST"])
def Login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    if username != "admin" or password != "admin":
        return jsonify({"msg":"Bad username or password"}) , 401
    
    response = jsonify({"msg":"Login Successful"})
    access_token = create_access_token(identity=username)
    
    set_access_cookies(response , access_token)
    
    client.set(username , f"oauth secret : {secrets.token_hex(32)}")
    
    return response

@app.route("/logout" , methods=["GET"])
def Logout():
    response = jsonify({"msg": "logout successful"})
    unset_jwt_cookies(response)
    return response

@app.route("/protected" , methods=["GET"])
@jwt_required(locations=["cookies"])
def Protected():
    data = {
        "current_user": get_jwt_identity(),
        "host": socket.gethostname(),
        "jwt_token": get_jwt(),
        "redis": client.get(get_jwt_identity())
    }
    return render_template("inside.html", data=data)

@app.route("/")
def Index():
    return render_template("index.html")

if __name__ == "__main__":
    app.run("0.0.0.0" , port=5000 , debug=True)
    
