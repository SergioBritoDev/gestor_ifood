# app.py  – Gestor iFood
import os, hmac, hashlib, datetime, json
from flask import Flask, render_template, request, abort
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Float,
    DateTime,
)
from sqlalchemy.orm import declarative_base, sessionmaker

# ─────────────────────────────────────────────────────────────
# 1. Flask e banco
app = Flask(__name__)

DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ─────────────────────────────────────────────────────────────
# 2. Modelo Pedido
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

# cria a tabela se ainda não existir
Base.metadata.create_all(engine)

# ─────────────────────────────────────────────────────────────
# 3. Rotas
@app.route("/")
def index():
    return "Gestor iFood online!"

@app.route("/pedidos")
def lista_pedidos():
    session = SessionLocal()
    pedidos = (
        session.query(Pedido)
        .order_by(Pedido.data_hora.desc())
        .all()
    )
    return render_template("pedidos.html", pedidos=pedidos)

# ─────────────────────────────────────────────────────────────
# 4. Helper de assinatura
def assinatura_valida(req):
    secret = os.environ["IFOOD_WEBHOOK_SECRET"].encode()
    corpo  = req.data
    calculada = hmac.new(secret, corpo, hashlib.sha1).hexdigest()
    recebida  = req.headers.get("X-Hub-Signature", "").split("sha1=")[-1]
    return hmac.compare_digest(calculada, recebida)

# ─────────────────────────────────────────────────────────────
# 5. Webhook
@app.route("/webhook", methods=["POST"])
def webhook():
        if not assinatura_valida(request):
        abort(401)

    payload = request.get_json(force=True)
    sess = SessionLocal()

    for order in payload.get("orders", []):
        order_id = order.get("id")
        created  = order.get("createdAt", datetime.datetime.utcnow().isoformat())
        status   = order.get("status", "PLACED")
        customer = order.get("customer", {}).get("name", "")
        total    = order.get("total", {}).get("amount", 0)
        fee      = order.get("commission", {}).get("amount", 0)

        for itm in order.get("items", []):
            if sess.query(Pedido).filter_by(
                pedido_id=order_id, item=itm.get("name", "")
            ).first():
                continue

            p = Pedido(
                pedido_id   = order_id,
                data_hora   = datetime.datetime.fromisoformat(
                              created.replace("Z", "+00:00")),
                status      = status,
                cliente     = customer,
                item        = itm.get("name", ""),
                quantidade  = itm.get("quantity", 1),
                total_bruto = total,
                taxa_ifood  = fee,
                total_liquido = total - fee,
            )
            sess.add(p)

    sess.commit()
    return "", 204