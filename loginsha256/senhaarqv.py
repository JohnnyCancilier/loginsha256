import bcrypt
import os
import pickle

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


def criar_usuario(nome, senha):
    salt = gerar_salt()
    senha_criptografada = criptografar_senha(senha, salt)

    # Salvar o usuário em um arquivo usando pickle
    usuario = {'nome': nome, 'senha': senha_criptografada, 'salt': salt}
    with open('usuarios.pkl', 'ab') as arquivo:
        pickle.dump(usuario, arquivo)

# Função para autenticar um usuário


def autenticar_usuario(nome, senha):
    try:
        # Carregar os usuários do arquivo
        with open('usuarios.pkl', 'rb') as arquivo:
            while True:
                try:
                    usuario = pickle.load(arquivo)
                    if usuario['nome'] == nome:
                        senha_criptografada = usuario['senha']
                        salt = usuario['salt']
                        if verificar_senha(senha, senha_criptografada):
                            return True
                except EOFError:
                    break
    except FileNotFoundError:
        pass

    return False


# Exemplo de uso
# Criar um novo usuário
nome_usuario = 'usuario1'
senha_usuario = 'senha123'
criar_usuario(nome_usuario, senha_usuario)
print(f'Usuário "{nome_usuario}" criado com sucesso!')

# Autenticar um usuário
nome_usuario = 'usuario1'
senha_usuario = 'senha123'
if autenticar_usuario(nome_usuario, senha_usuario):
    print(f'Usuário "{nome_usuario}" autenticado com sucesso!')
else:
    print(f'Falha na autenticação para o usuário "{nome_usuario}"')
