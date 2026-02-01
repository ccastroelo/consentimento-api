import os
import requests
from flask import Flask, render_template, jsonify, request, redirect, url_for

# --- Configuração Inicial ---
app = Flask(__name__)

# Pega as URLs das APIs a partir das variáveis de ambiente
URL_API_POLITICAS = os.environ.get('URL_API_POLITICAS')
URL_API_CONSENTIMENTOS = os.environ.get('URL_API_CONSENTIMENTOS')

# --- Rotas do Chatbot ---

@app.route('/')
def index():
    """Serve a página principal do chatbot (o index.html)"""
    return render_template('index.html')

@app.route('/get-latest-policy', methods=['GET'])
def get_latest_policy():
    """
    Endpoint de backend que o frontend (HTML) chama.
    Ele repassa a chamada para a API de Políticas.
    """
    try:
        # Chama a API de Políticas (comunicação interna do Docker)
        response = requests.get(f"{URL_API_POLITICAS}/policies/latest")
        response.raise_for_status() # Lança erro se a resposta não for 2xx
        return jsonify(response.json()), response.status_code
        
    except requests.exceptions.RequestException as e:
        # Trata erros de conexão ou se a API retornar erro
        error_message = f"Erro ao contatar API de Políticas: {e}"
        if e.response:
            error_message = e.response.json().get('error', str(e))
            return jsonify({"error": error_message}), e.response.status_code
        return jsonify({"error": error_message}), 503 # Service Unavailable

@app.route('/register-consent', methods=['POST'])
def register_consent():
    """
    Endpoint de backend que o frontend (HTML) chama.
    Ele repassa a chamada para a API de Consentimentos.
    """
    data = request.get_json()
    try:
        # Chama a API de Consentimentos (comunicação interna do Docker)
        response = requests.post(f"{URL_API_CONSENTIMENTOS}/consents", json=data)
        response.raise_for_status()
        return jsonify(response.json()), response.status_code

    except requests.exceptions.RequestException as e:
        error_message = f"Erro ao contatar API de Consentimentos: {e}"
        if e.response:
            error_message = e.response.json().get('error', str(e))
            return jsonify({"error": error_message}), e.response.status_code
        return jsonify({"error": error_message}), 503


# --- ROTAS DE ADMIN PARA UPLOAD DA POLÍTICA ---

@app.route('/admin')
def admin_page():
    """
    Serve a página HTML com o formulário de upload E A ÚLTIMA POLÍTICA.
    """
    latest_policy_info = None # Variável para guardar a info
    try:
        # Chama a API de Políticas (comunicação interna do Docker)
        response = requests.get(f"{URL_API_POLITICAS}/policies/latest")

        if response.status_code == 200:
            latest_policy_info = response.json() # Guarda o JSON da política
        elif response.status_code == 404:
            # Nenhuma política cadastrada, o que é ok
            pass 
        else:
            # Outro erro, mas não vamos quebrar a página de admin por isso
            print(f"Erro ao buscar latest policy: {response.text}") # Loga o erro no console do Docker

    except requests.exceptions.RequestException as e:
        print(f"Erro de conexão ao buscar latest policy: {str(e)}") # Loga o erro

    # Renderiza o template, passando a informação da política (pode ser None)
    return render_template('admin.html', latest_policy=latest_policy_info)

@app.route('/upload-policy', methods=['POST'])
def upload_policy_proxy():
    """
    Recebe o formulário da página /admin e o REPASSA para a api-politicas.
    Isto é um "proxy" para a API de políticas.
    """
    try:
        # 1. Obter os dados do formulário recebido
        form_data = {
            'version': request.form.get('version'),
            'description': request.form.get('description')
        }

        files = request.files.get('file')

        if not files:
            return "Erro: Nenhum arquivo enviado", 400

        # 2. Reempacotar os arquivos para a biblioteca requests
        # (filename, file-object, content-type)
        proxied_files = {
            'file': (files.filename, files.stream, files.mimetype)
        }

        # 3. Chamar a api-politicas (interna do Docker)
        response = requests.post(
            f"{URL_API_POLITICAS}/policies",
            files=proxied_files,
            data=form_data
        )

        # Lança um erro se a api-politicas falhar
        response.raise_for_status() 

        # 4. Se deu certo, redireciona de volta para a pág. de admin
        return redirect(url_for('admin_page'))

    except requests.exceptions.RequestException as e:
        # Se a api-politicas der erro (ex: hash duplicado), mostra o erro
        if e.response:
            return f"Erro ao enviar para API de Políticas: {e.response.json().get('error', str(e))}", e.response.status_code
        return f"Erro de conexão com a API de Políticas: {str(e)}", 503
    except Exception as e:
        return f"Erro interno no proxy: {str(e)}", 500

@app.route('/audit')
def audit_page():
    """
    Serve a página de auditoria, buscando os logs de um usuário.
    Espera um parâmetro na URL: /audit?user_id=...
    """
    user_id = request.args.get('user_id')
    if not user_id:
        return "ID de usuário não fornecido. Use a URL: /audit?user_id=123", 400
    consent_list = []
    try:
        # Chama a API de Consentimentos (comunicação interna do Docker)
        response = requests.get(f"{URL_API_CONSENTIMENTOS}/consents/user/{user_id}" )

        if response.status_code == 200:
            consent_list = response.json() # Lista de logs
        elif response.status_code == 404:
            # Usuário não tem logs, o que é ok. A lista fica vazia.
            pass 
        else:
            # Outros erros (500, etc)
            response.raise_for_status() 
    except requests.exceptions.RequestException as e:
        error_message = f"Erro ao contatar API de Consentimentos: {str(e)}"
        if e.response:
            error_message = e.response.json().get('error', str(e))
        return error_message, 503
    # Renderiza o novo template 'audit.html', passando as variáveis
    return render_template('audit.html', user_id=user_id, consents=consent_list)

#  --- Ponto de Partida ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
