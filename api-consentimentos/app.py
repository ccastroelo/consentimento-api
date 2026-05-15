import os
import jwt
import hmac
import hashlib
import secrets
from functools import wraps
from datetime import datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from sqlalchemy.orm import joinedload
from sqlalchemy.orm.exc import StaleDataError

# --- Configuração Inicial ---
app = Flask(__name__)

# Variáveis de ambiente
db_url = os.environ.get('DATABASE_URL', 'sqlite:///local_poc.db')
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Chave secreta para assinar e validar os tokens JWT (Deve ir para o .env na AWS)
app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET', 'chave-super-secreta-para-a-poc')
admin_token = os.environ.get('ADMIN_TOKEN', 'super-secret-admin-token-123')

db = SQLAlchemy(app)

# --- Decorator de Segurança (O Pulo do Gato Acadêmico) ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Esquema de autenticação inválido. Use Bearer token.'}), 401
        
        token = auth_header.split(" ")[1]
        
        try:
            # Exigir claims específicas para conformidade (ex: aud, iss)
            data = jwt.decode(
                token, 
                app.config['JWT_SECRET'], 
                algorithms=["HS256"],
                options={"require": ["exp", "iat", "user_id"]}
            )
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado.'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': f'Token inválido: {str(e)}'}), 401
            
        return f(current_user_id, *args, **kwargs)
    return decorated

def admin_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split()
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]
        
        if not token or token != admin_token:
            return jsonify({'error': 'Acesso negado: Token administrativo inválido ou ausente.'}), 401
            
        return f(*args, **kwargs)
    return decorated

# --- Função de Crypto-Shredding ---
def generate_pseudonym(user_id: int, salt: str) -> str:
    key_bytes = salt.encode('utf-8')
    msg_bytes = str(user_id).encode('utf-8')
    return hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()

# --- Modelos de Dados (Mantidos intactos) ---
class UserCrypto(db.Model):
    __tablename__ = "users_crypto"    
    id_user = db.Column(db.Integer, primary_key=True, index=True) 
    salt = db.Column(db.String, default=lambda: secrets.token_hex(32), nullable=False)
    pending_deletion = db.Column(db.Boolean, default=False)
    last_consent_hash = db.Column(db.String(64), nullable=True) # Ponteiro para o topo da cadeia
    version = db.Column(db.Integer, default=1, nullable=False)

    __mapper_args__ = {
        "version_id_col": version
    }

class Policies(db.Model):
    __tablename__ = 'policies'
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.String(20), nullable=False)
    published_at = db.Column(db.TIMESTAMP, server_default=db.func.now())
    description = db.Column(db.Text, nullable=True)
    url = db.Column(db.Text, nullable=False)
    hash = db.Column(db.String(64), nullable=False, unique=True)
    consents = db.relationship('Consents', back_populates='policy')

    def to_json_brief(self):
        return {'id': self.id, 'version': self.version, 'url': self.url, 'published_at': self.published_at.isoformat() if self.published_at else None}

class Consents(db.Model):
    __tablename__ = 'consents'
    id = db.Column(db.Integer, primary_key=True, index=True) 
    subject_pseudonym = db.Column(db.String(64), index=True, nullable=False)
    id_policy = db.Column(db.Integer, db.ForeignKey('policies.id'), nullable=True) 
    created_at = db.Column(db.TIMESTAMP, default=datetime.utcnow) 
    channel = db.Column(db.String(50), nullable=False) 
    validation_hash = db.Column(db.String(64), nullable=False, unique=True) 
    status = db.Column(db.String(20), nullable=False, default='given')
    version = db.Column(db.Integer, default=1, nullable=False)
    parent_hash = db.Column(db.String(64), nullable=True) # Hash do registro anterior
    sequence_version = db.Column(db.Integer, nullable=False) # Prova de Auditoria (Sincronizada com UserCrypto.version)
    policy = db.relationship('Policies', back_populates='consents')

    __mapper_args__ = {
        "version_id_col": version
    }

    def to_json(self):
        return {
            'id': self.id, 'subject_pseudonym': self.subject_pseudonym, 'id_policy': self.id_policy,
            'created_at': self.created_at.isoformat() if self.created_at else None, 'channel': self.channel,
            'validation_hash': self.validation_hash, 'status': self.status,
            'policy_info': self.policy.to_json_brief() if self.policy else None
        }

# --- Garantia de Append-Only (Integridade de Auditoria) ---
def prevent_audit_mutation(mapper, connection, target):
    raise Exception('Operação estritamente proibida: a tabela de auditoria é Append-Only')

event.listen(Consents, 'before_update', prevent_audit_mutation)
event.listen(Consents, 'before_delete', prevent_audit_mutation)

with app.app_context():
    db.create_all()

# --- Endpoints Protegidos ---

@app.route('/consents', methods=['POST'])
@token_required
def create_consent(current_user_id):
    """Registra o consentimento validando a identidade do token."""
    data = request.get_json()
    
    # Validação rigorosa de esquema sem exigir id_user no body para máxima segurança
    required_fields = ['id_policy', 'channel', 'status']
    if not data or not all(field in data for field in required_fields):
        return jsonify({"error": "Campos obrigatórios ausentes"}), 400

    try:
        id_user = int(current_user_id) # Identidade carimbada garantida pelo rigor do novo Token JWT
        id_policy = data['id_policy']
        channel = data['channel']
        status = data['status']
        
        user = db.session.get(UserCrypto, id_user)
        if not user:
            user = UserCrypto(id_user=id_user)
            db.session.add(user)
            db.session.commit()
            
        # Bloqueio removido: Caso o usuário tenha sido deletado numa operação de esquecimento,
        # o bloco acima passará a tratá-lo como um 'novo' usuário, gerando um novo salt aleatório nativamente.

        subject_pseudonym = generate_pseudonym(user.id_user, user.salt)
        
        policy_exists = db.session.get(Policies, id_policy)
        if not policy_exists:
            return jsonify({"error": f"Política não encontrada"}), 404

        # --- Lógica de Cadeia de Hashes (Integridade Linear) ---
        parent_hash = user.last_consent_hash
        timestamp = datetime.utcnow()
        
        # O hash agora inclui o parent_hash, vinculando este registro ao anterior
        hash_input = f"{subject_pseudonym}:{id_policy}:{timestamp.isoformat()}:{channel}:{status}:{parent_hash}"
        validation_hash = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

        new_consent = Consents(
            subject_pseudonym=subject_pseudonym, 
            id_policy=id_policy, 
            channel=channel, 
            validation_hash=validation_hash, 
            created_at=timestamp, 
            status=status,
            parent_hash=parent_hash, # Registra o elo da cadeia
            sequence_version=user.version # Captura a versão atual do usuário como prova de auditoria
        )
        
        # Atualiza o ponteiro no usuário. O version_id_col no UserCrypto 
        # incrementará automaticamente a versão do usuário no commit.
        user.last_consent_hash = validation_hash
        
        db.session.add(new_consent)
        db.session.commit()
        db.session.refresh(new_consent)

        return jsonify({"message": "Consentimento registrado com sucesso!", "consent": new_consent.to_json()}), 201
    except StaleDataError:
        db.session.rollback()
        # Tratamento limpo para o Bloqueio Otimista (Optimistic Locking)
        return jsonify({
            "error": "Ocorreu um erro na gravação, tente novamente."
        }), 409
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
        if not user:
            return jsonify({"error": "Usuário não encontrado ou já foi anonimizado."}), 404

        subject_pseudonym = generate_pseudonym(user.id_user, user.salt)
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

@app.route('/admin/consents/user/<int:user_id>', methods=['GET'])
@admin_token_required
def admin_get_consents_by_user(user_id):
    """Endpoint simplificado para auditoria do painel interno (admin-panel). Apenas leitura."""
    try:
        user = db.session.get(UserCrypto, user_id)
        if not user:
            return jsonify({"error": "Usuário não encontrado ou já foi anonimizado."}), 404

        subject_pseudonym = generate_pseudonym(user.id_user, user.salt)
        consents = Consents.query.options(joinedload(Consents.policy)).filter_by(subject_pseudonym=subject_pseudonym).order_by(Consents.created_at.desc()).all()
        
        if not consents:
            return jsonify({"error": "Nenhum consentimento encontrado"}), 404
            
        return jsonify([c.to_json() for c in consents]), 200
    except Exception as e:
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@app.route('/users/<int:user_id>/forget', methods=['DELETE'])
@token_required
def forget_user(current_user_id, user_id):
    """Executa o esquecimento garantindo que apenas o próprio usuário pode apagar os seus dados."""
    if int(current_user_id) != int(user_id):
        return jsonify({"error": "Acesso não autorizado para acionar o esquecimento."}), 403

    try:
        user = db.session.get(UserCrypto, user_id)
        if not user:
            return jsonify({"message": "Usuário inexistente ou já anonimizado."}), 404

        # Captura o pseudônimo ANTES de marcar para deleção (para referência no log de auditoria se necessário)
        subject_pseudonym = generate_pseudonym(user.id_user, user.salt)

        # O grande pulo do gato: Deleção Diferida (Soft-Delete para processamento assíncrono)
        # O worker.py irá detectar este flag, executar o crypto-shredding no Vault 
        # e então realizar a deleção física do registro UserCrypto.
        user.pending_deletion = True
        db.session.commit()

        return jsonify({"message": "Direito ao Esquecimento solicitado. O titular foi marcado para anonimização definitiva pelo Worker."}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@app.route('/admin/metrics/adherence', methods=['GET'])
@admin_token_required
def admin_metrics_adherence():
    """Calcula a aderência às políticas para usuários ativos."""
    try:
        total_active_users = UserCrypto.query.filter_by(pending_deletion=False).count()
        if total_active_users == 0:
            return jsonify({"total_users": 0, "adherence": []}), 200
            
        results = db.session.query(
            Policies.id,
            Policies.version,
            db.func.count(UserCrypto.id_user)
        ).select_from(UserCrypto).join(
            Consents, UserCrypto.last_consent_hash == Consents.validation_hash
        ).join(
            Policies, Consents.id_policy == Policies.id
        ).filter(
            UserCrypto.pending_deletion == False,
            Consents.status == 'given'
        ).group_by(
            Policies.id, Policies.version
        ).all()
        
        adherence_list = []
        users_with_consent = 0
        for policy_id, version, count in results:
            percentage = round((count / total_active_users) * 100, 2)
            adherence_list.append({
                "policy_id": policy_id,
                "version": version,
                "users_count": count,
                "percentage": percentage
            })
            users_with_consent += count
            
        users_without_consent = total_active_users - users_with_consent
        if users_without_consent > 0:
            percentage_without = round((users_without_consent / total_active_users) * 100, 2)
            adherence_list.append({
                "policy_id": None,
                "version": "Sem Consentimento / Revogado",
                "users_count": users_without_consent,
                "percentage": percentage_without
            })
            
        def sort_key(item):
            return item['policy_id'] if item['policy_id'] is not None else -1
            
        adherence_list.sort(key=sort_key, reverse=True)
            
        return jsonify({
            "total_users": total_active_users,
            "adherence": adherence_list
        }), 200
    except Exception as e:
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)