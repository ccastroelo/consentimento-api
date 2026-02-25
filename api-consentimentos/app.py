import os
import jwt
import hmac
import hashlib
import secrets
from functools import wraps
from datetime import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload

# --- Configuração Inicial ---
app = Flask(__name__)

# Variáveis de ambiente
db_url = os.environ.get('DATABASE_URL', 'sqlite:///local_poc.db')
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Chave secreta para assinar e validar os tokens JWT (Deve ir para o .env na AWS)
app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET', 'chave-super-secreta-para-a-poc')

db = SQLAlchemy(app)

# --- Decorator de Segurança (O Pulo do Gato Acadêmico) ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Verifica se o cabeçalho Authorization está presente
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split()
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]
        
        if not token:
            return jsonify({'error': 'Acesso negado: Token de autenticação ausente.'}), 401
        
        try:
            # Decodifica o token para extrair a identidade real do usuário
            data = jwt.decode(token, app.config['JWT_SECRET'], algorithms=["HS256"])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Acesso negado: Token expirado.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Acesso negado: Token inválido.'}), 401
            
        # Injeta o ID extraído do token na função protegida
        return f(current_user_id, *args, **kwargs)
    return decorated

# --- Função de Crypto-Shredding ---
def generate_pseudonym(user_id: int, secret_key: str) -> str:
    key_bytes = secret_key.encode('utf-8')
    msg_bytes = str(user_id).encode('utf-8')
    return hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()

# --- Modelos de Dados (Mantidos intactos) ---
class UserCrypto(db.Model):
    __tablename__ = "users_crypto"    
    id_user = db.Column(db.Integer, primary_key=True, index=True) 
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
        return {'id': self.id, 'version': self.version, 'published_at': self.published_at.isoformat() if self.published_at else None}

class Consents(db.Model):
    __tablename__ = 'consents'
    id = db.Column(db.Integer, primary_key=True, index=True) 
    subject_pseudonym = db.Column(db.String(64), index=True, nullable=False)
    id_policy = db.Column(db.Integer, db.ForeignKey('policies.id'), nullable=False) 
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow) 
    channel = db.Column(db.String(50), nullable=False) 
    validation_hash = db.Column(db.String(64), nullable=False, unique=True) 
    status = db.Column(db.String(20), nullable=False, default='given')
    policy = db.relationship('Policies', back_populates='consents')

    def to_json(self):
        return {
            'id': self.id, 'subject_pseudonym': self.subject_pseudonym, 'id_policy': self.id_policy,
            'created_at': self.created_at.isoformat() if self.created_at else None, 'channel': self.channel,
            'validation_hash': self.validation_hash, 'status': self.status,
            'policy_info': self.policy.to_json_brief() if self.policy else None
        }

with app.app_context():
    db.create_all()

# --- Endpoints Protegidos ---

@app.route('/consents', methods=['POST'])
@token_required
def create_consent(current_user_id):
    """Registra o consentimento validando a identidade do token."""
    data = request.get_json()
    
    if not data or 'id_user' not in data or 'id_policy' not in data or 'channel' not in data or 'status' not in data:
        return jsonify({"error": "Dados incompletos"}), 400

    # A REGRA DE OURO DA AUTORIZAÇÃO: O ID do corpo do JSON deve casar com o ID do Token assinado.
    if int(data['id_user']) != int(current_user_id):
        return jsonify({"error": "Conflito de Identidade: O titular do token não tem permissão para assinar por outro usuário."}), 403

    try:
        id_user = int(current_user_id) # Usamos a identidade validada criptograficamente
        id_policy = data['id_policy']
        channel = data['channel']
        status = data['status']
        
        user = db.session.get(UserCrypto, id_user)
        if not user:
            user = UserCrypto(id_user=id_user)
            db.session.add(user)
            db.session.commit()
            
        if not user.secret_key:
            return jsonify({"error": "Titular anonimizado. Não é possível registrar novos dados."}), 403

        subject_pseudonym = generate_pseudonym(user.id_user, user.secret_key)
        
        policy_exists = db.session.get(Policies, id_policy)
        if not policy_exists:
            return jsonify({"error": f"Política não encontrada"}), 404

        timestamp = datetime.utcnow()
        hash_input = f"{subject_pseudonym}:{id_policy}:{timestamp.isoformat()}:{channel}:{status}"
        validation_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

        new_consent = Consents(subject_pseudonym=subject_pseudonym, id_policy=id_policy, channel=channel, validation_hash=validation_hash, created_at=timestamp, status=status)
        db.session.add(new_consent)
        db.session.commit()
        db.session.refresh(new_consent)

        return jsonify({"message": "Consentimento registrado com sucesso!", "consent": new_consent.to_json()}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@app.route('/consents/user/<int:user_id>', methods=['GET'])
@token_required
def get_consents_by_user(current_user_id, user_id):
    """Consulta o histórico garantindo que o usuário só veja os seus próprios dados."""
    if int(current_user_id) != int(user_id):
        return jsonify({"error": "Acesso não autorizado ao histórico de terceiros."}), 403

    try:
        user = db.session.get(UserCrypto, user_id)
        if not user or not user.secret_key:
            return jsonify({"error": "Usuário não encontrado ou já foi anonimizado."}), 404

        subject_pseudonym = generate_pseudonym(user.id_user, user.secret_key)
        consents = Consents.query.options(joinedload(Consents.policy)).filter_by(subject_pseudonym=subject_pseudonym).order_by(Consents.created_at.desc()).all()
        
        if not consents:
            return jsonify({"error": "Nenhum consentimento encontrado"}), 404
            
        return jsonify([c.to_json() for c in consents]), 200
    except Exception as e:
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@app.route('/consents/policy/<int:policy_id>', methods=['GET'])
def get_consents_by_policy(policy_id):
    """(Este endpoint pode ficar aberto para auditoria, pois os usuários estão pseudonimizados)"""
    # ... (código original mantido) ...
    pass # Coloque aqui o seu código original de get_consents_by_policy

@app.route('/users/<int:user_id>/forget', methods=['DELETE'])
@token_required
def forget_user(current_user_id, user_id):
    """Executa o esquecimento garantindo que apenas o próprio usuário pode apagar os seus dados."""
    if int(current_user_id) != int(user_id):
        return jsonify({"error": "Acesso não autorizado para acionar o esquecimento."}), 403

    try:
        user = db.session.get(UserCrypto, user_id)
        if not user or not user.secret_key:
            return jsonify({"message": "Usuário já anonimizado ou inexistente."}), 404
        
        user.secret_key = None
        db.session.commit()
        
        return jsonify({"message": "Direito ao Esquecimento aplicado."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)