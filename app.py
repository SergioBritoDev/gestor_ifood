from flask import Flask, request, abort, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
import datetime, os, hmac, hashlib, json

# Flask e banco
app = Flask(__name__)
DATABASE_URL = os.environ.get("DATABASE_URL")
WEBHOOK_SECRET = os.environ.get("IFOOD_WEBHOOK_SECRET")

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine)

# Modelo do banco
class Pedido(Base):
    __tablename__ = "pedidos"
    id            = Column(Integer, primary_key=True)
    pedido_id     = Column(String, unique=True, nullable=False)
    data_hora     = Column(DateTime, default=datetime.datetime.utcnow)
    status        = Column(String)
    cliente       = Column(String)
    item          = Column(String)
    quantidade    = Column(Integer)
    total_bruto   = Column(Float)
    taxa_ifood    = Column(Float)
    total_liquido = Column(Float)

# Cria as tabelas se ainda não existem
Base.metadata.create_all(engine)

# Sessão de banco
session = SessionLocal()

# Rota do webhook
@app.route("/webhook", methods=["POST"])
def webhook():
    signature = request.headers.get("X-Hub-Signature", "").split("sha1=")[-1]
    payload = request.get_data()
    hash = hmac.new(WEBHOOK_SECRET.encode(), payload, hashlib.sha1).hexdigest()
    
    if not hmac.compare_digest(signature, hash):
        abort(401)

    data = json.loads(payload)
    for order in data.get("orders", []):
        order_id   = order.get("id")
        status     = order.get("status")
        cliente    = order.get("customer", {}).get("name")
        item       = order.get("items", [{}])[0].get("name")
        quantidade = order.get("items", [{}])[0].get("quantity")
        total_bruto = order.get("total", 0)
        taxa_ifood  = order.get("commission", 0)
        total_liquido = total_bruto - taxa_ifood

        existente = session.query(Pedido).filter_by(pedido_id=order_id).first()
        if not existente:
            novo = Pedido(
                pedido_id     = order_id,
                data_hora     = datetime.datetime.utcnow(),
                status        = status,
                cliente       = cliente,
                item          = item,
                quantidade    = quantidade,
                total_bruto   = total_bruto,
                taxa_ifood    = taxa_ifood,
                total_liquido = total_liquido
            )
            session.add(novo)
            session.commit()
    return "", 204

# Página com listagem de pedidos
@app.route("/pedidos")
def pedidos():
    pedidos = session.query(Pedido).order_by(Pedido.data_hora.desc()).all()
    return render_template("pedidos.html", pedidos=pedidos)

# Painel Admin
admin = Admin(app, name="Painel de Pedidos", template_mode="bootstrap4")
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return abort(403)

admin.add_view(SecureModelView(Pedido, session))

from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

# Login básico (usuário fixo)
login_manager = LoginManager(app)
login_manager.login_view = "login"

class AdminUser(UserMixin):
    id = 1
    username = "Sergio"
    password = "Semsenha14#"  # Troque por algo mais seguro

    def get_id(self):
        return str(self.id)

@login_manager.user_loader
def load_user(user_id):
    return AdminUser()

# Login via formulário HTML simples
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.form["username"] == "Sergio" and request.form["password"] == "Semsenha14#":
            login_user(AdminUser())
            return "Logado com sucesso! <a href='/admin'>Ir para o painel</a>"
        else:
            return "Credenciais inválidas."
    return '''
    <form method="post">
        Usuário: <input type="text" name="username"><br>
        Senha: <input type="password" name="password"><br>
        <input type="submit" value="Entrar">
    </form>
    '''

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return "Saiu com sucesso! <a href='/login'>Login</a>"

# Home
@app.route("/")
def home():
    return "Gestor iFood online!"

