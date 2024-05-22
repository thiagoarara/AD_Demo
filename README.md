# AD_Demo
Funcionalidades básicas de manipulação do AD com python

## Pré-requisitos

=> Python 3;<br>
=> PIP<br>
=> Acesso ao Active Directory.

## Guia

=> Instalar o python3 e o python3-pip;<br>
=> pip install -r requirements.txt<br>


## Observações

### 1. Esqueci minha senha
 => **Precisa** de usuário privilegiado para executar esta opção;<br>
 => Precisa executar em LDAPS;<br>
 => Ignora a política de rotação de senhas do AD levando em consideração apenas a política de tamanho de senha;<br>
 => Não precisa saber a senha antiga para atribuir a nova senha.<br>
 
### 2. Alterar senha
 => **Não precisa** de usuário privilegiado para executar esta opção;<br>
 => Precisa executar em LDAPS;<br>
 => Segue a política de senhas do AD;<br>
 => Precisa saber a senha antiga para atribuir a nova senha.<br>
