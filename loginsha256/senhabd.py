import bcrypt
import sqlite3

# Função para gerar um salt


def gerar_salt():
    return bcrypt.gensalt().decode('utf-8')

# Função para criptografar a senha com o salt


def criptografar_senha(senha, salt):
    senha_bytes = senha.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    senha_criptografada = bcrypt.hashpw(senha_bytes, salt_bytes)
    return senha_criptografada.decode('utf-8')

# Função para verificar se a senha é válida


def verificar_senha(senha, senha_criptografada):
    senha_bytes = senha.encode('utf-8')
    senha_criptografada_bytes = senha_criptografada.encode('utf-8')
    return bcrypt.checkpw(senha_bytes, senha_criptografada_bytes)

# Função para criar um novo usuário


def criar_usuario(conn, nome, senha):
    salt = gerar_salt()
    senha_criptografada = criptografar_senha(senha, salt)

    cursor = conn.cursor()
    cursor.execute('INSERT INTO usuarios (nome, senha, salt) VALUES (?, ?, ?)',
                   (nome, senha_criptografada, salt))
    conn.commit()

# Função para autenticar um usuário


def autenticar_usuario(conn, nome, senha):
    cursor = conn.cursor()
    cursor.execute('SELECT senha, salt FROM usuarios WHERE nome = ?', (nome,))
    resultado = cursor.fetchone()

    if resultado:
        senha_criptografada, salt = resultado
        senha_criptografada = senha_criptografada.decode('utf-8')
        salt = salt.decode('utf-8')

        if verificar_senha(senha, senha_criptografada):
            return True

    return False


# Exemplo de uso
# Conectar ao banco de dados
conn = sqlite3.connect('usuarios.db')

# Criar a tabela de usuários (se não existir)
cursor = conn.cursor()
cursor.execute(
    'CREATE TABLE IF NOT EXISTS usuarios (nome TEXT PRIMARY KEY, senha TEXT, salt TEXT)')

# Criar um novo usuário
criar_usuario(conn, 'usuario1', 'senha123')

# Autenticar um usuário
nome_usuario = 'usuario1'
senha_usuario = 'senha123'
if autenticar_usuario(conn, nome_usuario, senha_usuario):
    print(f'Usuário "{nome_usuario}" autenticado com sucesso!')
else:
    print(f'Falha na autenticação para o usuário "{nome_usuario}"')

# Fechar a conexão com o banco de dados
conn.close()
