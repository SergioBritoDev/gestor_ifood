import os
import hmac
import hashlib
from datetime import datetime
from flask import Flask, request, redirect, url_for, render_template, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "default-secret")

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode="threading")

# MODELOS
class AdminUser(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False, unique=True)
    password = db.Column(db.String(128), nullable=False)

class Produto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    categoria = db.Column(db.String(100))
    descricao = db.Column(db.Text)
    imagem = db.Column(db.String(255))
    ficha_tecnica = db.Column(db.Text)
    pdv = db.Column(db.String(100))

class Pedido(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pedido_id = db.Column(db.String(100))
    data_hora = db.Column(db.DateTime, default=datetime.utcnow)
    cliente = db.Column(db.String(100))
    item = db.Column(db.String(255))
    quantidade = db.Column(db.Integer)
    total_liquido = db.Column(db.Float)
    status = db.Column(db.String(50), default="pendente")

# LOGIN
login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return AdminUser.query.get(int(user_id))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nome = request.form["username"]
        senha = request.form["password"]
        user = AdminUser.query.filter_by(username=nome, 
password=senha).first()
        if user:
            login_user(user)
            return redirect(url_for("admin.index"))
        return "Usuário ou senha inválidos", 401
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ADMIN
class ProtectedModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

admin = Admin(app, name="Gestor iFood", template_mode="bootstrap3")
admin.add_view(ProtectedModelView(AdminUser, db.session))
admin.add_view(ProtectedModelView(Produto, db.session))
admin.add_view(ProtectedModelView(Pedido, db.session))

# WEBHOOK
@app.route("/webhook", methods=["POST"])
def webhook():
    signature = request.headers.get("X-Hub-Signature")
    secret = os.environ.get("IFOOD_SECRET", "")
    payload = request.data
    hash_obj = hmac.new(secret.encode(), payload, hashlib.sha1)
    expected_signature = f"sha1={hash_obj.hexdigest()}"

    if not hmac.compare_digest(signature or "", expected_signature):
        return "Assinatura inválida", 401

    pedido_json = request.json
    novo = Pedido(
        pedido_id=pedido_json.get("id", "sem_id"),
        cliente=pedido_json.get("cliente", "desconhecido"),
        item=pedido_json.get("item", "item desconhecido"),
        quantidade=pedido_json.get("quantidade", 1),
        total_liquido=pedido_json.get("total_liquido", 0.0),
        status="pendente"
    )
    db.session.add(novo)
    db.session.commit()

    socketio.emit("novo_pedido", {
        "id": novo.id,
        "cliente": novo.cliente,
        "item": novo.item,
        "quantidade": novo.quantidade
    })

    return "OK", 200

# KDS
@app.route("/kds")
def kds():
    pedidos = Pedido.query.filter_by(status="pendente").order_by(Pedido.data_hora.desc()).all()
    return render_template("kds.html", pedidos=pedidos)

@socketio.on("pedido_finalizado")
def finalizar_pedido(data):
    pedido = Pedido.query.get(data.get("id"))
    if pedido:
        pedido.status = "finalizado"
        db.session.commit()
        emit("pedido_removido", {"id": pedido.id}, broadcast=True)

# NOVA ROTA: API para retornar os pedidos pendentes (usada pelo KDS)
@app.route("/api/pedidos")
def api_pedidos():
    pedidos = Pedido.query.filter_by(status="pendente").order_by(Pedido.data_hora.desc()).all()
    return jsonify([{
        "id": p.id,
        "cliente": p.cliente,
        "item": p.item,
        "quantidade": p.quantidade,
        "total_liquido": p.total_liquido,
        "data_hora": p.data_hora.isoformat()
    } for p in pedidos])

# RODAR
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), allow_unsafe_werkzeug=True)

