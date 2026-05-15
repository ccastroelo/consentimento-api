import os
import requests
from flask import Flask, render_template, jsonify, request, redirect, url_for

# --- Configuração Inicial ---
app = Flask(__name__)

# Pega as URLs das APIs a partir das variáveis de ambiente
URL_API_POLITICAS = os.environ.get('URL_API_POLITICAS')
URL_API_CONSENTIMENTOS = os.environ.get('URL_API_CONSENTIMENTOS')
ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN', 'super-secret-admin-token-123')

# --- Rotas do Admin Panel ---

@app.route('/')
def index():
    """Redireciona a raiz para a página de gestão de políticas"""
    return redirect(url_for('admin_page'))


# --- ROTAS DE ADMIN PARA UPLOAD DA POLÍTICA ---

@app.route('/admin')
def admin_page():
    """
    Serve a página HTML com o formulário de upload E A ÚLTIMA POLÍTICA.
    """
    latest_policy_info = None # Variável para guardar a info da última
    all_policies = []         # Variável para o histórico
    try:
        # Chama a API de Políticas para pegar todas as versões
        response = requests.get(f"{URL_API_POLITICAS}/policies")

        if response.status_code == 200:
            all_policies = response.json() # Lista de políticas (descendente)
            if all_policies:
                latest_policy_info = all_policies[0] # A mais recente é a primeira
        else:
            print(f"Erro ao buscar policies: {response.text}") 

    except requests.exceptions.RequestException as e:
        print(f"Erro de conexão ao buscar policies: {str(e)}") # Loga o erro

    # --- NOVA CHAMADA: Busca métricas de aderência ---
    adherence_info = None
    try:
        headers = {'Authorization': f'Bearer {ADMIN_TOKEN}'}
        response_adherence = requests.get(
            f"{URL_API_CONSENTIMENTOS}/admin/metrics/adherence", 
            headers=headers
        )
        if response_adherence.status_code == 200:
            adherence_info = response_adherence.json()
        else:
            print(f"Erro ao buscar aderência: Status {response_adherence.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Erro de conexão ao buscar métricas de aderência: {str(e)}")

    # Renderiza o template, passando a informação da política e dados de aderência
    return render_template('admin.html', latest_policy=latest_policy_info, adherence_data=adherence_info, all_policies=all_policies)

@app.route('/verify-policy/<int:policy_id>', methods=['POST'])
def verify_policy_proxy(policy_id):
    """
    Proxy que repassa a solicitação de verificação para a api-politicas.
    """
    try:
        headers = {'Authorization': f'Bearer {ADMIN_TOKEN}'}
        response = requests.get(
            f"{URL_API_POLITICAS}/policies/{policy_id}/verify",
            headers=headers
        )
        return jsonify(response.json()), response.status_code
    except Exception as e:
        return jsonify({"error": f"Erro interno no proxy: {str(e)}"}), 500

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
        headers = {'Authorization': f'Bearer {ADMIN_TOKEN}'}
        response = requests.post(
            f"{URL_API_POLITICAS}/policies",
            files=proxied_files,
            data=form_data,
            headers=headers
        )

        # Lança um erro se a api-politicas falhar
        response.raise_for_status() 

        # 4. Se deu certo, redireciona de volta para a pág. de admin
        return redirect(url_for('admin_page'))

    except requests.exceptions.RequestException as e:
        # Se a api-politicas der erro (ex: hash duplicado), mostra o erro
        if e.response is not None:
            try:
                error_msg = e.response.json().get('error', str(e))
            except ValueError:
                error_msg = e.response.text
            return f"Erro ao enviar para API de Políticas: {error_msg}", e.response.status_code
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
        # Chama a API de Consentimentos na rota administrativa (comunicação interna do Docker)
        headers = {'Authorization': f'Bearer {ADMIN_TOKEN}'}
        response = requests.get(
            f"{URL_API_CONSENTIMENTOS}/admin/consents/user/{user_id}",
            headers=headers
        )

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
        if e.response is not None:
            try:
                error_message = e.response.json().get('error', str(e))
            except ValueError:
                error_message = e.response.text
        return error_message, 503
    # Renderiza o novo template 'audit.html', passando as variáveis
    return render_template('audit.html', user_id=user_id, consents=consent_list)

#  --- Ponto de Partida ---
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
