# Usa uma imagem base leve do Python
FROM python:3.10-slim

# Define o diretório de trabalho dentro do contêiner
WORKDIR /app

# Copia o arquivo de dependências
COPY requirements.txt .

# Instala as dependências
RUN pip install -r requirements.txt

# Copia o restante do código da aplicação
COPY . .

# Expõe a porta
EXPOSE 5000

# Comando para rodar a app
CMD ["flask", "run", "--host=0.0.0.0"]
