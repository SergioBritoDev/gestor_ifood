# app.py  —  Gestor iFood
from flask import Flask, render_template, request, abort
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
import os, datetime, hmac, hashlib, json

# ───────────────────────────────────────────────────────────────────
# 1. Configuração básica
app = Flask(__name__)

engine = create_engine(os.environ["DATABASE_URL"])
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ───────────────────────────────────────────────────────────────────
# 2. Modelo Pedido  (caso ainda não exista em models.py)
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

# ───────────────────────────────────────────────────────────────────
# 3. Rota principal
@app.route("/")
def index():
    return "Gestor iFood online!"

# ───────────────────────────────────────────────────────────────────
# 4. Rota de listagem de pedidos
@app.route("/pedidos")
def lista_pedidos():
    session = SessionLocal()
    pedidos = session.query(Pedido).order_by(Pedido.data_hora.desc()).all()
    return render_template("pedidos.html", pedidos=pedidos)

# ───────────────────────────────────────────────────────────────────
# 5. Função para validar assinatura do iFood
def assinatura_valida(req):
    secret = os.environ["IFOOD_WEBHOOK_SECRET"].encode()
    corpo  = req.data
    calculada = hmac.new(secret, corpo, hashlib.sha1).hexdigest()
    recebida  = req.headers.get("X-Hub-Signature", "").split("sha1=")[-1]
    return hmac.compare_digest(calculada, recebida)

# ───────────────────────────────────────────────────────────────────
# 6. Rota /webhook  (recebe pedidos do iFood)
@app.route("/webhook", methods=["POST"])
def webhook():
    if not assinatura_valida(request):
        abort(401)

    payload = request.get_json(force=True)
    sess = SessionLocal()

    for order in payload.get("orders", []):
        for itm in order.get("items", []):
            p = Pedido(
                pedido_id   = order_id,
                data_hora   = datetime.datetime.fromisoformat(
                                created.replace("Z","+00:00")),
                status      = status,
                cliente     = customer,
                item        = itm.get("name", ""),
                quantidade  = itm.get("quantity", 1),
                total_bruto = total,
                taxa_ifood  = fee,
                total_liquido = total - fee,
            )
            sess.add(p)
            sess.merge(p)            # atualiza se já existir
    sess.commit()
    return "", 204
