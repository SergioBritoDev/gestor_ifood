import os
import hmac
import json
import hashlib
import datetime

from flask import Flask, request, abort, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# Configuração inicial
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "chave-insegura")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ["DATABASE_URL"]
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Tabela de pedidos
class Pedido(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    pedido_id     = db.Column(db.String, unique=True, nullable=False)
    data_hora     = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    status        = db.Column(db.String)
    cliente       = db.Column(db.String)
    item          = db.Column(db.String)
    quantidade    = db.Column(db.Integer)
    total_bruto   = db.Column(db.Float)
    taxa_ifood    = db.Column(db.Float)
    total_liquido = db.Column(db.Float)

# Tabela de usuário admin
class AdminUser(UserMixin, db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)

# Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return AdminUser.query.get(int(user_id))

# Painel Admin
class AuthenticatedModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

admin = Admin(app, name="Gestor iFood", template_mode="bootstrap4")
admin.add_view(AuthenticatedModelView(Pedido, db.session))
admin.add_view(AuthenticatedModelView(AdminUser, db.session))

# Rotas
@app.route("/")
def index():
    return "Gestor iFood online!"

@app.route("/pedidos")
def pedidos():
    todos = Pedido.query.order_by(Pedido.data_hora.desc()).all()
    return render_template("pedidos.html", pedidos=todos)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nome = request.form.get("username")
        senha = request.form.get("password")
        user = AdminUser.query.filter_by(username=nome, password=senha).first()
        if user:
            login_user(user)
            return redirect("/admin")
        else:
            return "Credenciais inválidas", 401
    return '''
        <form method="post">
            Usuário: <input name="username"><br>
            Senha: <input name="password" type="password"><br>
            <button type="submit">Entrar</button>
        </form>
    '''

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/webhook", methods=["POST"])
def webhook():
    secret = os.environ.get("IFOOD_WEBHOOK_SECRET", "")
    signature = request.headers.get("X-Hub-Signature", "").replace("sha1=", "")
    body = request.get_data()
    expected = hmac.new(secret.encode(), body, hashlib.sha1).hexdigest()
    if not hmac.compare_digest(signature, expected):
        abort(401)

    payload = json.loads(body)
    for order in payload.get("orders", []):
        order_id = order.get("id")
        if not Pedido.query.filter_by(pedido_id=order_id).first():
            novo = Pedido(
                pedido_id   = order_id,
                data_hora   = datetime.datetime.strptime(order["createdAt"], "%Y-%m-%dT%H:%M:%SZ"),
                status      = order.get("status"),
                cliente     = order.get("customer", {}).get("name"),
                item        = order.get("items", [{}])[0].get("name"),
                quantidade  = order.get("items", [{}])[0].get("quantity"),
                total_bruto = order.get("price"),
                taxa_ifood  = order.get("commission"),
                total_liquido = order.get("price", 0) - order.get("commission", 0)
            )
            db.session.add(novo)
    db.session.commit()
    return "", 204

