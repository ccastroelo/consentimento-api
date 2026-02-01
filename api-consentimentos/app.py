import os
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload

# --- Configuração Inicial ---
app = Flask(__name__)

# Carrega as variáveis de ambiente
db_url = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
db = SQLAlchemy(app)

# --- Modelos de Dados (Tabelas Policies e Consents) ---
class Policies(db.Model):
    __tablename__ = 'policies'
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(20), nullable=False)
    published_at = db.Column(db.TIMESTAMP, server_default=db.func.now())
    description = db.Column(db.Text, nullable=True)
    s3_url = db.Column(db.Text, nullable=False)
    hash_sha256 = db.Column(db.String(64), nullable=False, unique=True)
    
    # Relação
    consents = db.relationship('Consents', back_populates='policy')

    def to_json_brief(self):
        return {
            'id': self.id,
            'version': self.version,
            'published_at': self.published_at.isoformat()
        }

class Consents(db.Model):
    __tablename__ = 'consents'
    id = db.Column(db.Integer, primary_key=True) 
    id_user = db.Column(db.Integer, nullable=False, index=True) 
    id_policy = db.Column(db.Integer, db.ForeignKey('policies.id'), nullable=False) 
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow) 
    channel = db.Column(db.String(50), nullable=False) 
    validation_hash = db.Column(db.String(64), nullable=False, unique=True) 
    status = db.Column(db.String(20), nullable=False, default='given') # (given, refused, revoked)
    
    # Relação
    policy = db.relationship('Policies', back_populates='consents')

    def to_json(self):
        return {
            'id': self.id,
            'id_user': self.id_user,
            'id_policy': self.id_policy,
            'created_at': self.created_at.isoformat(),
            'channel': self.channel,
            'validation_hash': self.validation_hash,
            'status': self.status,
            # Inclui dados da política vinculada, se carregados
            'policy_info': self.policy.to_json_brief() if self.policy else None
        }

# --- CRIA AS TABELAS ---
with app.app_context():
    db.create_all()

# --- Endpoints da API ---
@app.route('/consents', methods=['POST'])
def create_consent():
    """
    Endpoint para registrar um novo consentimento.
    Espera um JSON com:
    - 'id_user'
    - 'id_policy'
    - 'channel'
    """
    data = request.get_json()
    if not data or 'id_user' not in data or 'id_policy' not in data or 'channel' not in data or 'status' not in data:
        return jsonify({"error": "Campos 'id_user', 'id_policy', 'channel' e 'status' são obrigatórios"}), 400

    try:
        id_user = data['id_user']
        id_policy = data['id_policy']
        channel = data['channel']
        status = data['status']
        if status not in ['given', 'refused']:
            return jsonify({"error": "Status deve ser 'given' ou 'refused'"}), 400
        timestamp = datetime.utcnow().isoformat()

        # 1. Gerar Hash de Integridade 
        hash_input = f"{id_user}:{id_policy}:{timestamp}:{channel}:{status}" # Adiciona status ao hash
        validation_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

        # 2. Verificar se a política existe
        policy_exists = db.session.get(Policies, id_policy)
        if not policy_exists:
            return jsonify({"error": f"Política com id={id_policy} não encontrada"}), 404

        # 3. Salvar no Banco
        new_consent = Consents(
            id_user=id_user,
            id_policy=id_policy,
            channel=channel,
            validation_hash=validation_hash,
            created_at=datetime.fromisoformat(timestamp),
            status=status
        )
        db.session.add(new_consent)
        db.session.commit()

        # Recarregar o objeto para popular a relação policy
        db.session.refresh(new_consent)

        return jsonify({"message": "Consentimento registrado com sucesso!", "consent": new_consent.to_json()}), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@app.route('/consents/user/<int:user_id>', methods=['GET'])
def get_consents_by_user(user_id):
    """
    Endpoint para retornar o histórico de consentimentos de um usuário. 
    """
    try:
        # 'joinedload' para fazer o JOIN com a tabela Policies e já carregar os dados da política
        consents = Consents.query.options(joinedload(Consents.policy)).filter_by(id_user=user_id).order_by(Consents.created_at.desc()).all()
        
        if not consents:
            return jsonify({"error": "Nenhum consentimento encontrado para este usuário"}), 404
            
        return jsonify([c.to_json() for c in consents]), 200
    except Exception as e:
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@app.route('/consents/policy/<int:policy_id>', methods=['GET'])
def get_consents_by_policy(policy_id):
    """
    Endpoint para listar consentimentos vinculados a uma política específica. 
    """
    try:
        # Verifica se a política existe primeiro.
        policy_exists = db.session.get(Policies, policy_id)
        if not policy_exists:
            return jsonify({"error": f"Política com id={policy_id} não encontrada"}), 404

        consents = Consents.query.filter_by(id_policy=policy_id).all()
        
        if not consents:
            return jsonify({"message": "Nenhum consentimento encontrado para esta política"}), 200

        # Retorna uma versão simples do Json
        return jsonify([
            {
                'id': c.id,
                'id_user': c.id_user,
                'created_at': c.created_at.isoformat(),
                'channel': c.channel
            } for c in consents
        ]), 200
    except Exception as e:
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500


# --- Inicio ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
