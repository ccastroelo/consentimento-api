import os
import requests
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

URL_API_POLITICAS = os.environ.get('URL_API_POLITICAS')
URL_API_CONSENTIMENTOS = os.environ.get('URL_API_CONSENTIMENTOS')

@app.route('/')
def index():
    return render_template('chat.html')

@app.route('/api/policy', methods=['GET'])
def get_policy():
    try:
        resp = requests.get(f"{URL_API_POLITICAS}/policies/latest")
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/consent', methods=['POST'])
def record_consent():
    data = request.json
    try:
        resp = requests.post(f"{URL_API_CONSENTIMENTOS}/consents", json=data)
        return jsonify(resp.json()), resp.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
