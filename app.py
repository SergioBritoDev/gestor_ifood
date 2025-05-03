import os
from flask import Flask, request, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import hmac
import hashlib
from flask import abort

# Configurações
app = Flask(__name__)
app.secret_key = "segredo-super-seguro"
DATABASE_URL = os.environ["DATABASE_URL"]
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
admin = Admin(app, name="Painel Admin", template_mode="bootstrap3")

# Modelos
class Pedido(db.Model):
    __tablename__ = "pedidos"
    id = db.Column(db.Integer, primary_key=True)
    pedido_id = db.Column(db.String, unique=True, nullable=False)
    status = db.Column(db.String)
    cliente = db.Column(db.String)
    item = db.Column(db.String)
    quantidade = db.Column(db.Integer)
    total_bruto = db.Column(db.Float)
    taxa_ifood = db.Column(db.Float)
    total_liquido = db.Column(db.Float)
    data_hora = db.Column(db.DateTime, default=datetime.utcnow)

class AdminUser(UserMixin, db.Model):
    __tablename__ = "admin_user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

# Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(AdminUser, int(user_id))

# Painel admin protegido
class ProtectedModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

admin.add_view(ProtectedModelView(Pedido, db.session))

# Rotas
@app.route("/")
def index():
    return "Gestor iFood online!"

@app.route("/pedidos")
@login_required
def listar_pedidos():
    pedidos = Pedido.query.order_by(Pedido.data_hora.desc()).all()
    return render_template("pedidos.html", pedidos=pedidos)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nome = request.form["username"]
        senha = request.form["password"]
        user = AdminUser.query.filter_by(username=nome, password=senha).first()
        if user:
            login_user(user)
            return redirect("/admin")
        else:
            return "Credenciais inválidas", 401
    return '''
        <form method="post">
            Usuário: <input type="text" name="username"><br>
            Senha: <input type="password" name="password"><br>
            <input type="submit" value="Entrar">
        </form>
    '''

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/webhook", methods=["POST"])
def webhook():
    secret = os.environ.get("IFOOD_WEBHOOK_SECRET", "")
    assinatura = request.headers.get("X-Hub-Signature", "")
    corpo = request.get_data()

    hash_local = hmac.new(secret.encode(), corpo, hashlib.sha1).hexdigest()
    if not hmac.compare_digest(f"sha1={hash_local}", assinatura):
        abort(401)

    payload = request.get_json()
    for order in payload.get("orders", []):
        order_id = order.get("id")
        if Pedido.query.filter_by(pedido_id=order_id).first():
            continue
        pedido = Pedido(
            pedido_id=order_id,
            status=order.get("status"),
            cliente=order.get("customer", {}).get("name", "Cliente"),
            item=order.get("items", [{}])[0].get("name"),
            quantidade=order.get("items", [{}])[0].get("quantity"),
            total_bruto=order.get("totalPrice"),
            taxa_ifood=order.get("commission"),
            total_liquido=order.get("totalPrice") - order.get("commission", 0),
        )
        db.session.add(pedido)
    db.session.commit()
    return "", 204

