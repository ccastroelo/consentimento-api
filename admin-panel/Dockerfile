# Usa uma imagem base leve do Python
FROM python:3.10-slim

# Define o diretório de trabalho
WORKDIR /app

# Copia e instala as dependências
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copia o restante da aplicação (incluindo a pasta templates)
COPY . .

# Expõe a porta
EXPOSE 5000

# Comando para rodar a app
CMD ["flask", "run", "--host=0.0.0.0"]
