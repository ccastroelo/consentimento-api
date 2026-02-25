import os
import requests
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

# Adicionado um fallback para o ambiente local caso a variável falhe
URL_API_POLITICAS = os.environ.get('URL_API_POLITICAS', 'http://api-politicas:5000')
URL_API_CONSENTIMENTOS = os.environ.get('URL_API_CONSENTIMENTOS', 'http://api-consentimentos:5000')

@app.route('/')
def index():
    return render_template('chat.html')

@app.route('/api/policy', methods=['GET'])
def get_policy():
    try:
        resp = requests.get(f"{URL_API_POLITICAS}/policies/latest")
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Falha de comunicação com a API de Políticas: {str(e)}"}), 500

@app.route('/api/consent', methods=['POST'])
def record_consent():
    data = request.json
    try:
        # Repassa o payload (id_user, id_policy, channel, status)
        resp = requests.post(f"{URL_API_CONSENTIMENTOS}/consents", json=data)
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Falha de comunicação com a API de Consentimentos: {str(e)}"}), 500

# --- NOVAS ROTAS OBRIGATÓRIAS PARA A LGPD ---

@app.route('/api/consent/history/<int:user_id>', methods=['GET'])
def get_history(user_id):
    """Consulta o histórico de consentimentos de um titular."""
    try:
        resp = requests.get(f"{URL_API_CONSENTIMENTOS}/consents/user/{user_id}")
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Falha ao buscar histórico: {str(e)}"}), 500

@app.route('/api/consent/forget/<int:user_id>', methods=['DELETE'])
def forget_user(user_id):
    """Aciona o Direito ao Esquecimento (Crypto-Shredding)."""
    try:
        resp = requests.delete(f"{URL_API_CONSENTIMENTOS}/users/{user_id}/forget")
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Falha ao processar o direito ao esquecimento: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)