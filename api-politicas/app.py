import os
import hashlib
import boto3
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from botocore.client import Config
from botocore.exceptions import NoCredentialsError

# --- Configuração Inicial ---
app = Flask(__name__)

# Carrega as variáveis de ambiente do docker-compose
db_url = os.environ.get('DATABASE_URL')
minio_url_internal = os.environ.get('MINIO_URL')
minio_url_public = os.environ.get('MINIO_PUBLIC_URL')
minio_access_key = os.environ.get('MINIO_ACCESS_KEY')
minio_secret_key = os.environ.get('MINIO_SECRET_KEY')
minio_bucket = os.environ.get('MINIO_BUCKET', 'politicas')

# Configura o SQLAlchemy (Banco de Dados)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
db = SQLAlchemy(app)

# Configura o Boto3 (Cliente MinIO/S3)
# Usamos 's3' como service_name, pois MinIO é compatível com a API do S3
s3_client = boto3.client(
    's3',
    endpoint_url=minio_url_internal,
    aws_access_key_id=minio_access_key,
    aws_secret_access_key=minio_secret_key,
    config=Config(signature_version='s3v4')
)

# --- Modelo de Dados (Tabela Policies) ---
# Define a estrutura da tabela no PostgreSQL [cite: 3373, 3374]
class Policies(db.Model):
    __tablename__ = 'policies' # Nome da tabela como na sua dissertação
    id = db.Column(db.Integer, primary_key=True) # Usei Integer auto-incrementável (mais simples que UUID para PK)
    version = db.Column(db.String(20), nullable=False) # 'versao' [cite: 3374]
    published_at = db.Column(db.TIMESTAMP, server_default=db.func.now()) # 'criado_em' [cite: 3374]
    description = db.Column(db.Text, nullable=True) # 'descricao' [cite: 3374]
    s3_url = db.Column(db.Text, nullable=False) # 's3_url' [cite: 3374]
    hash_sha256 = db.Column(db.String(64), nullable=False, unique=True) # 'hash_sha256' [cite: 3374]

    def to_json(self):
        return {
            'id': self.id,
            'version': self.version,
            'published_at': self.published_at.isoformat(),
            'description': self.description,
            's3_url': self.s3_url,
            'hash_sha256': self.hash_sha256
        }

# -- CRIA AS TABELAS  ---
with app.app_context():
    db.create_all()

# --- Endpoints da API ---

@app.route('/policies', methods=['POST'])
def create_policy():
    """
    Endpoint para cadastrar uma nova política de privacidade.
    Espera um formulário 'multipart/form-data' com os campos:
    - 'file': O documento da política (PDF, etc.)
    - 'version': A versão semântica (ex: "1.0.0")
    - 'description': Um breve resumo das mudanças
    """
    # 1. Validação de entrada
    if 'file' not in request.files:
        return jsonify({"error": "Nenhum arquivo enviado"}), 400

    file = request.files['file']
    version = request.form.get('version')
    description = request.form.get('description')

    if not file or not version:
        return jsonify({"error": "Campos 'file' e 'version' são obrigatórios"}), 400

    try:
        file_content = file.read()

        # 2. Calcular Hash (Integridade)
        hash_sha256 = hashlib.sha256(file_content).hexdigest()

        # Verifica se essa versão de hash já existe
        existing = Policies.query.filter_by(hash_sha256=hash_sha256).first()
        if existing:
            return jsonify({"error": "Uma política com este mesmo conteúdo (hash) já existe", "policy": existing.to_json()}), 409 # Conflict

        # 3. Upload para o MinIO/S3
        # Nome do objeto no bucket
        object_name = f"{hash_sha256}-{file.filename}" 

        # Reposiciona o ponteiro do arquivo para o início antes do upload
        file.seek(0) 

        content_type = file.content_type or 'application/pdf'

        s3_client.upload_fileobj(
            file,
            minio_bucket,
            object_name,
            ExtraArgs={
                'ContentType': content_type,
                'ContentDisposition': 'inline'
            }
        )

        s3_url = f"{minio_url_public}/{minio_bucket}/{object_name}"

        # 4. Salvar Metadados no PostgreSQL
        new_policy = Policies(
            version=version,
            description=description,
            s3_url=s3_url,
            hash_sha256=hash_sha256
        )
        db.session.add(new_policy)
        db.session.commit()

        return jsonify({"message": "Política criada com sucesso!", "policy": new_policy.to_json()}), 201

    except NoCredentialsError:
        return jsonify({"error": "Credenciais do S3 não configuradas"}), 500
    except Exception as e:
        db.session.rollback()
        print(f"ERRO NO UPLOAD: {str(e)}")
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@app.route('/policies/latest', methods=['GET'])
def get_latest_policy():
    """
    Endpoint para obter a política de privacidade mais recente (última publicada).
    """
    try:
        latest_policy = Policies.query.order_by(Policies.published_at.desc()).first()
        if not latest_policy:
            return jsonify({"error": "Nenhuma política encontrada"}), 404
 
        return jsonify(latest_policy.to_json()), 200
    except Exception as e:
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

@app.route('/policies', methods=['GET'])
def get_all_policies():
    """
    Endpoint para listar todas as versões de políticas.
    """
    try:
        policies = Policies.query.order_by(Policies.published_at.desc()).all()
        return jsonify([p.to_json() for p in policies]), 200
    except Exception as e:
        return jsonify({"error": f"Erro interno: {str(e)}"}), 500

# --- Ponto de Partida ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
