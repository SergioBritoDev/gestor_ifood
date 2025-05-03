from flask import Flask, request, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit
from datetime import datetime
import os
import hmac
import hashlib
import json

app = Flask(__name__)
app.secret_key = "supersecret"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]
db = SQLAlchemy(app)
socketio = SocketIO(app)

login_manager = LoginManager(app)

### MODELOS
class AdminUser(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class Pedido(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pedido_id = db.Column(db.String, unique=True)
    data_hora = db.Column(db.DateTime)
    cliente = db.Column(db.String)
    item = db.Column(db.String)
    quantidade = db.Column(db.Integer)
    total_liquido = db.Column(db.Float)
    status = db.Column(db.String, default="pendente")

class Produto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(120))
    categoria = db.Column(db.String(120))
    descricao = db.Column(db.Text)
    imagem = db.Column(db.String(300))
    ficha_tecnica = db.Column(db.Text)
    pdv = db.Column(db.String(120))

### LOGIN
@login_manager.user_loader
def load_user(user_id):
    return AdminUser.query.get(int(user_id))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nome = request.form["username"]
        senha = request.form["password"]
        user = AdminUser.query.filter_by(username=nome, password=senha).first()
        if user:
            login_user(user)
            return redirect("/admin")
        return "Usuário ou senha inválidos"
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")

### FLASK ADMIN
admin = Admin(app, name="Painel", template_mode="bootstrap3")
admin.add_view(ModelView(Pedido, db.session))
admin.add_view(ModelView(Produto, db.session))
admin.add_view(ModelView(AdminUser, db.session))

### ROTAS KDS
@app.route("/kds")
def kds():
    pedidos = Pedido.query.filter(Pedido.status == "pendente").order_by(Pedido.data_hora.desc()).all()
    return render_template("kds.html", pedidos=pedidos)

@app.route("/atualizar-status/<int:pedido_id>", methods=["POST"])
def atualizar_status(pedido_id):
    pedido = Pedido.query.get(pedido_id)
    if pedido:
        pedido.status = "pronto"
        db.session.commit()
        socketio.emit("atualizar_pedidos", broadcast=True)
    return ("", 204)

### ROTAS PEDIDOS
@app.route("/pedidos")
def listar_pedidos():
    pedidos = Pedido.query.order_by(Pedido.data_hora.desc()).all()
    return render_template("pedidos.html", pedidos=pedidos)

@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.get_data()
    signature = request.headers.get("X-Hub-Signature", "").replace("sha1=", "")
    secret = b"Semsenha14#"

    expected_signature = hmac.new(secret, payload, hashlib.sha1).hexdigest()

    print("🔐 Assinatura recebida:", signature)
    print("✅ Assinatura esperada:", expected_signature)
    print("📦 Payload recebido:", payload.decode("utf-8"))

    if not hmac.compare_digest(signature, expected_signature):
        return "Assinatura inválida", 401

    data = json.loads(payload)

    for order in data.get("orders", []):
        order_id = order.get("order_id")
        cliente = order.get("customer", {}).get("name", "Cliente")
        for item in order.get("items", []):
            nome_item = item.get("name")
            quantidade = item.get("quantity", 1)
            total = item.get("total", 0)

            novo_pedido = Pedido(
                pedido_id=order_id,
                cliente=cliente,
                item=nome_item,
                quantidade=quantidade,
                total_liquido=total,
                status="pendente"
            )
            db.session.add(novo_pedido)

    db.session.commit()

    # Emite para o KDS
    socketio.emit("novo_pedido", {"pedido_id": order_id})
    return "", 204

### EXECUÇÃO
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)

