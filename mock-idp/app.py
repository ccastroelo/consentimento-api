import os
import datetime
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# A chave secreta DEVE ser a mesma que a api-consentimentos usa para validar.
# Na AWS, ambas lerão do ficheiro .env
app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET', 'chave-super-secreta-para-a-poc')

@app.route('/auth/mock-login', methods=['POST'])
def mock_login():
    """Simula o Provedor de Identidade (IdP)"""
    data = request.get_json()
    
    if not data or 'user_id' not in data:
        return jsonify({'error': 'user_id é obrigatório para o login simulado'}), 400
        
    user_id = data['user_id']
    
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
        'iat': datetime.datetime.utcnow(),
        'iss': 'poc-mestrado-idp'
    }
    
    token = jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')
    
    return jsonify({
        'message': 'Login simulado com sucesso.',
        'token': token,
        'user_id': user_id
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)