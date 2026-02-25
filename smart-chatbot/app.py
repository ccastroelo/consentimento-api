import os
import requests
from flask import Flask, render_template, jsonify, request, session

app = Flask(__name__)

# OBRIGATÓRIO: A secret_key é necessária para assinar os cookies de sessão do Flask.
# Em produção (AWS), isso DEVE vir do seu arquivo .env.
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'chave-super-segura-para-sessao-do-chatbot')

URL_API_POLITICAS = os.environ.get('URL_API_POLITICAS', 'http://api-politicas:5000')
URL_API_CONSENTIMENTOS = os.environ.get('URL_API_CONSENTIMENTOS', 'http://api-consentimentos:5000')
URL_MOCK_IDP = os.environ.get('URL_MOCK_IDP', 'http://mock-idp:5000') # Nova dependência

# --- FUNÇÃO AUXILIAR DE SEGURANÇA ---
def get_auth_headers():
    """Recupera o token da sessão e monta o cabeçalho de autorização."""
    token = session.get('jwt_token')
    if not token:
        return None
    return {'Authorization': f'Bearer {token}'}

@app.route('/')
def index():
    return render_template('chat.html')

# --- 1. NOVA ROTA: LOGIN E GESTÃO DE IDENTIDADE ---
@app.route('/api/auth/login', methods=['POST'])
def login():
    """Solicita o token JWT ao Provedor de Identidade e guarda na sessão."""
    data = request.json
    user_id = data.get('user_id')
    
    if not user_id:
        return jsonify({"error": "ID de usuário ausente"}), 400

    try:
        resp = requests.post(f"{URL_MOCK_IDP}/auth/mock-login", json={"user_id": int(user_id)})
        
        if resp.status_code == 200:
            # Armazena as credenciais de forma segura na sessão do usuário
            session['jwt_token'] = resp.json().get('token')
            session['user_id'] = int(user_id)
            return jsonify({"message": "Identidade confirmada com sucesso"}), 200
            
        return jsonify({"error": "Falha na autenticação do provedor de identidade"}), resp.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Falha de comunicação com o IdP: {str(e)}"}), 500

# --- 2. ROTAS PÚBLICAS ---
@app.route('/api/policy', methods=['GET'])
def get_policy():
    """A leitura da política vigente pode permanecer pública."""
    try:
        resp = requests.get(f"{URL_API_POLITICAS}/policies/latest")
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Falha de comunicação com a API de Políticas: {str(e)}"}), 500

# --- 3. ROTAS PROTEGIDAS (EXIGEM TOKEN JWT) ---
@app.route('/api/consent', methods=['POST'])
def record_consent():
    """Registra o consentimento anexando a prova de identidade (JWT)."""
    headers = get_auth_headers()
    if not headers:
        return jsonify({"error": "Não autorizado. O usuário deve se identificar primeiro."}), 401

    data = request.json
    
    # Validação de segurança dupla: o ID enviado na requisição deve casar com o ID da sessão
    if int(data.get('id_user')) != session.get('user_id'):
        return jsonify({"error": "Conflito de identidade detectado."}), 403

    try:
        resp = requests.post(f"{URL_API_CONSENTIMENTOS}/consents", json=data, headers=headers)
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Falha de comunicação com a API de Consentimentos: {str(e)}"}), 500

@app.route('/api/consent/history/<int:user_id>', methods=['GET'])
def get_history(user_id):
    """Consulta o histórico usando autenticação."""
    headers = get_auth_headers()
    if not headers:
        return jsonify({"error": "Não autorizado."}), 401

    if user_id != session.get('user_id'):
        return jsonify({"error": "Acesso negado aos dados de terceiros."}), 403

    try:
        resp = requests.get(f"{URL_API_CONSENTIMENTOS}/consents/user/{user_id}", headers=headers)
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Falha ao buscar histórico: {str(e)}"}), 500

@app.route('/api/consent/forget/<int:user_id>', methods=['DELETE'])
def forget_user(user_id):
    """Aciona o Crypto-Shredding e destrói a sessão."""
    headers = get_auth_headers()
    if not headers:
        return jsonify({"error": "Não autorizado."}), 401

    if user_id != session.get('user_id'):
        return jsonify({"error": "Acesso negado para excluir dados de terceiros."}), 403

    try:
        resp = requests.delete(f"{URL_API_CONSENTIMENTOS}/users/{user_id}/forget", headers=headers)
        
        # Se o esquecimento for bem-sucedido, a identidade foi apagada. Devemos limpar a sessão local.
        if resp.status_code == 200:
            session.clear()
            
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Falha ao processar o direito ao esquecimento: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)