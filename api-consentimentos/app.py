import os
import hmac
import hashlib
import secrets
from datetime import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload

# --- Configuração Inicial ---
app = Flask(__name__)

# Carrega as variáveis de ambiente (com fallback para testes locais)
db_url = os.environ.get('DATABASE_URL', 'sqlite:///local_poc.db')
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Função de Crypto-Shredding (Pseudonimização) ---
def generate_pseudonym(user_id: int, secret_key: str) -> str:
    """Gera um HMAC-SHA256 irreversível ligando o usuário à sua chave."""
    key_bytes = secret_key.encode('utf-8')
    msg_bytes = str(user_id).encode('utf-8')
    return hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()

# --- Modelos de Dados ---
class UserCrypto(db.Model):
    __tablename__ = "users_crypto"    
    id_user = db.Column(db.Integer, primary_key=True, index=True) 
    # nullable=True para permitir o esquecimento (apagar a chave)
    secret_key = db.Column(db.String, default=lambda: secrets.token_hex(32), nullable=True)

class Policies(db.Model):
    __tablename__ = 'policies'
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(20), nullable=False)
    published_at = db.Column(db.TIMESTAMP, server_default=db.func.now())
    description = db.Column(db.Text, nullable=True)
    s3_url = db.Column(db.Text, nullable=False)
    hash_sha256 = db.Column(db.String(64), nullable=False, unique=True)
    
    consents = db.relationship('Consents', back_populates='policy')

    def to_json_brief(self):
        return {
            'id': self.id,
            'version': self.version,
            'published_at': self.published_at.isoformat() if self.published_at else None
        }

class Consents(db.Model):
    __tablename__ = 'consents'
    id = db.Column(db.Integer, primary_key=True, index=True) 
    
    # Armazena apenas a string criptografada
    subject_pseudonym = db.Column(db.String(64), index=True, nullable=False)
    
    id_policy = db.Column(db.Integer, db.ForeignKey('policies.id'), nullable=False) 
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow) 
    channel = db.Column(db.String(50), nullable=False) 
    validation_hash = db.Column(db.String(64), nullable=False, unique=True) 
    status = db.Column(db.String(20), nullable=False, default='given')
    
    policy = db.relationship('Policies', back_populates='consents')

    def to_json(self):
        return {
            'id': self.id,
            'subject_pseudonym': self.subject_pseudonym,
            'id_policy': self.id_policy,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'channel': self.channel,
            'validation_hash': self.validation_hash,
            'status': self.status,
            'policy_info': self.policy.to_json_brief() if self.policy else None
        }

# --- CRIA AS TABELAS ---
with app.app_context():
    db.create_all()

# --- Endpoints da API ---
@app.route('/consents', methods=['POST'])
def create_consent():
    """Registra o consentimento anonimizando o titular em tempo real."""
    data = request.get_json()
    
    # A API recebe o id_user em texto claro, mas NÃO o salva!
    if not data or 'id_user' not in data or 'id_policy' not in data or 'channel' not in data or 'status' not in data:
        return jsonify({"error": "Campos 'id_user', 'id_policy', 'channel' e 'status' são obrigatórios"}), 400

    try:
        id_user = data['id_user']
        id_policy = data['id_policy']
        channel = data['channel']
        status = data['status']
        if status not in ['given', 'refused']:
            return jsonify({"error": "Status deve ser 'given' ou 'refused'"}), 400
        
        # 1. Busca ou cria o usuário na tabela de criptografia
        user = db.session.get(UserCrypto, id_user)
        if not user:
            user = UserCrypto(id_user=id_user)
            db.session.add(user)
            db.session.commit()
            
        # Bloqueio: Se a chave foi deletada, o usuário foi esquecido.
        if not user.secret_key:
            return jsonify({"error": "Titular anonimizado. Não é possível registrar novos dados."}), 403

        # 2. Gerar o Pseudônimo (Magia do Crypto-Shredding)
        subject_pseudonym = generate_pseudonym(user.id_user, user.secret_key)
        
        # 3. Verificar se a política existe
        policy_exists = db.session.get(Policies, id_policy)
        if not policy_exists:
            return jsonify({"error": f"Política com id={id_policy} não encontrada"}), 404

        timestamp = datetime.utcnow()

        # 4. Hash de Validação (Usa o pseudônimo, protegendo a identidade do titular)
        hash_input = f"{subject_pseudonym}:{id_policy}:{timestamp.isoformat()}:{channel}:{status}"
        validation_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

        # 5. Salvar no Banco
        new_consent = Consents(
            subject_pseudonym=subject_pseudonym,
            id_policy=id_policy,
            channel=channel,
            validation_hash=validation_hash,
            created_at=timestamp,
            status=status
        )
        db.session.add(new_consent)
        db.session.commit()
        db.session.refresh(new_consent)

        return jsonify({"message": "Consentimento registrado com pseudônimo criptográfico!", "consent": new_consent.to_json()}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@app.route('/consents/user/<int:user_id>', methods=['GET'])
def get_consents_by_user(user_id):
    """Reconstrói a identidade temporariamente apenas para consulta do histórico."""
    try:
        user = db.session.get(UserCrypto, user_id)
        if not user or not user.secret_key:
            return jsonify({"error": "Usuário não encontrado ou já foi anonimizado (Direito ao Esquecimento)."}), 404

        # Recalcula o pseudônimo para fazer a busca
        subject_pseudonym = generate_pseudonym(user.id_user, user.secret_key)
        
        consents = Consents.query.options(joinedload(Consents.policy)).filter_by(subject_pseudonym=subject_pseudonym).order_by(Consents.created_at.desc()).all()
        
        if not consents:
            return jsonify({"error": "Nenhum consentimento encontrado"}), 404
            
        return jsonify([c.to_json() for c in consents]), 200
    except Exception as e:
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@app.route('/consents/policy/<int:policy_id>', methods=['GET'])
def get_consents_by_policy(policy_id):
    """Lista consentimentos sem expor quem são os usuários reais."""
    try:
        policy_exists = db.session.get(Policies, policy_id)
        if not policy_exists:
            return jsonify({"error": f"Política com id={policy_id} não encontrada"}), 404

        consents = Consents.query.filter_by(id_policy=policy_id).all()
        if not consents:
            return jsonify({"message": "Nenhum consentimento encontrado para esta política"}), 200

        return jsonify([
            {
                'id': c.id,
                'subject_pseudonym': c.subject_pseudonym,
                'created_at': c.created_at.isoformat() if c.created_at else None,
                'channel': c.channel
            } for c in consents
        ]), 200
    except Exception as e:
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@app.route('/users/<int:user_id>/forget', methods=['DELETE'])
def forget_user(user_id):
    """Endpoint de Crypto-Shredding: Aplica o Direito ao Esquecimento."""
    try:
        user = db.session.get(UserCrypto, user_id)
        if not user or not user.secret_key:
            return jsonify({"message": "Usuário já anonimizado ou inexistente."}), 404
        
        # O PULO DO GATO: Deleta a chave, quebrando a criptografia para sempre
        user.secret_key = None
        db.session.commit()
        
        return jsonify({"message": "Direito ao Esquecimento aplicado. A trilha de auditoria foi preservada, mas a identidade está irrevogavelmente anonimizada."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

# --- Inicio ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)