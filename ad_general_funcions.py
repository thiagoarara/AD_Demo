
import ldap3
from ldap3 import get_config_parameter
import string
import unicodedata
import unidecode
# from ldap3.extend.microsoft.modifyPassword import ad_modify_password



SERVIDOR = '<IP do servidor AD>'

BASE_LDAP = "dc=ad-demo,dc=local"


### Credencial privilegiada (nao deixar no código)

USUARIO = "AD-DEMO\\user_priv"
SENHA = "Passw0rdPriv!"

### Fim credencial privilegiada

FILTER = "(|(samAccountName=*))"
ATTRS = ['*']

NORMAL_ACCOUNT = 512
DISABLE_ACCOUNT = 514


## raise ldap3.core.exceptions.LDAPExceptionError
def search_user_by_field(field_name, field_value, SEARCH_BASE, ATTRIBUTES_FILTER_ARRAY = ['*']):
    """

    :param field_name: The field name
    :param field_value: The field value
    :param SEARCH_BASE: The AD search tree
    :param ATTRIBUTES_FILTER_ARRAY: An array with attributes that will be filtred on Resultset return
    :return: A result search list

    :raises ldap3.core.exceptions.LDAPExceptionError: exception from AD library
    """
    retorno = ()

    server = ldap3.Server(SERVIDOR, use_ssl=True, get_info=ldap3.ALL)
    conn = ldap3.Connection(server, user=USUARIO, password=SENHA, auto_bind=True, raise_exceptions=False)

    conn.search(search_base=SEARCH_BASE, search_filter='(&({}={}))'.format(field_name, field_value),
                search_scope=ldap3.SUBTREE, attributes=ATTRIBUTES_FILTER_ARRAY, get_operational_attributes=True)

    # print(f"Response\n{conn.response}")

    for entry in conn.entries:
        retorno += (entry),



    return retorno


def move_user(current_distinguished_name, target_distinguished_name):

    """
    General function to move an A.D. object to other Common Name

    :param current_distinguished_name: Current user Distinguished Name
    (eg.: CN=AD User 1,OU=Usuarios Ativos,DC=AD-DEMO,DC=local)
    :param target_distinguished_name: Target Common Name without user part
    (eg.: CN=AD User 1,OU=Usuarios Inativos,DC=AD-DEMO,DC=local)
    :return: True if the AD element was moved without error and False otherwise
    :raises ldap3.core.exceptions.LDAPExceptionError: exception from AD library

    """
    # print("DN:{}".format(current_distinguished_name))
    # print("Target_DN:{}".format(target_distinguished_name))
    retorno = False

    if current_distinguished_name is not None and target_distinguished_name is not None:

        server = ldap3.Server(SERVIDOR, use_ssl=True, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user=USUARIO, password=SENHA, auto_bind=True, raise_exceptions=False)

        user_CN = current_distinguished_name.split(',')[0]
        # print("USER_CN:{}".format(user_CN))
        target_DN = target_distinguished_name
        if user_CN in target_distinguished_name:
            target_DN = target_distinguished_name.replace("{},".format(user_CN), "")

        try:
            retorno = conn.modify_dn(
                dn=current_distinguished_name,
                relative_dn=user_CN,
                new_superior=target_DN,
                delete_old_dn=True
            )

        except ldap3.core.exceptions.LDAPExceptionError:
            print("Move operation error!")

    return retorno

def invert_account_status(account):

    """
    Disable account if the passed account is enabled and Enables otherwise

    :param account: The Active Directory Object
    :return: True if the status modify action performed without error and False otherwise
    :raises ldap3.core.exceptions.LDAPExceptionError: exception from AD library

    """

    retorno = False

    if account is not None:
        # print(account)
        print("{}=={}".format(int("{}".format(account["userAccountControl"])),NORMAL_ACCOUNT))

        try:
            if int("{}".format(account["userAccountControl"])) == DISABLE_ACCOUNT:
                target_status = "{}".format(NORMAL_ACCOUNT)
            elif int("{}".format(account["userAccountControl"])) == NORMAL_ACCOUNT:
                target_status = "{}".format(DISABLE_ACCOUNT)

            server = ldap3.Server(SERVIDOR, use_ssl=True, get_info=ldap3.ALL)
            conn = ldap3.Connection(server, user=USUARIO, password=SENHA, auto_bind=True, raise_exceptions=False)
            modify_account = [(ldap3.MODIFY_REPLACE, [target_status])]
            DN = "{}".format(account["distinguishedName"])
            retorno = conn.modify(DN,
                                  {'userAccountControl': modify_account},
                                  controls=None)
        except ldap3.core.exceptions.LDAPCursorError:
            print("The object without userAccountControl attribute")


    return retorno


def forgot_password(account, passwd):
    """

    :param account: The account that password will be changed
    :param passwd: The password
    :return: True if it was with no errors and False otherwise
    :raises: m_ex.PasswordSetError: If the Active Directory returns False

    """
    retorno = False
    if (passwd is not None):

        pass_quoted = '\"{}\"'.format(passwd).encode()

        unicode_pass = str(pass_quoted, 'iso-8859-1')

        password_value = unicode_pass.encode('utf-16-le')

        add_pass = [(ldap3.MODIFY_REPLACE, [password_value])]
        DN = "{}".format(account["distinguishedName"])

        server = ldap3.Server(SERVIDOR, use_ssl=True, get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user=USUARIO, password=SENHA, auto_bind=True, raise_exceptions=False)
        retorno_passwd = conn.modify(DN, {'unicodePwd': add_pass}, controls=None)
        if retorno_passwd == False:
            print("Error when trying to set the password")

        # print(retorno_passwd)
        target_status = "{}".format(NORMAL_ACCOUNT)

        modify_account = [(ldap3.MODIFY_REPLACE, [target_status])]
        retorno = conn.modify(DN,
                              {'userAccountControl': modify_account},
                              controls=None)
        # print(retorno)

    return retorno


def search_user(field_name, field_value, SEARCH_BASE, usuario, senha, ATTRIBUTES_FILTER_ARRAY = ['*']):

    retorno = ()
    server = ldap3.Server(SERVIDOR, use_ssl=True, get_info=ldap3.ALL)
    conn = ldap3.Connection(server, user=usuario, password=senha, auto_bind=True, raise_exceptions=True)

    # conn.bind()
    conn.search(search_base=SEARCH_BASE, search_filter='(&({}={}))'.format(field_name, field_value),
                search_scope=ldap3.SUBTREE, attributes=ATTRIBUTES_FILTER_ARRAY, get_operational_attributes=True)

    for entry in conn.entries:
        
        retorno += (entry),

    conn.unbind()

    return retorno

def change_password(dn_pack, senha_anterior, senha_nova, usuario):
    
    server = ldap3.Server(SERVIDOR, use_ssl=True, get_info=ldap3.ALL)
    conn = ldap3.Connection(server, user=usuario, password=senha_anterior, auto_bind=True, raise_exceptions=True)
    # conn.start_tls()
    try:
        retorno = ldap3.extend.microsoft.modifyPassword.ad_modify_password(conn, f"{dn_pack}", 
                new_password=senha_nova, 
                old_password=senha_anterior)
        
#        print(retorno)
#        print(conn.result)
        
    except Exception as e:
        print("Houve algum problema na modificação de senha no AD")
        
        print(e)
        print(conn.request)
        retorno = e

    conn.unbind()

    return retorno

####  TESTS AREA  ####

#ret = search_user("<atributo_do_ad>", "<valor_procurado>", "<raiz_de busca_do_ad>", '<usuario_do_dominio>', "<senha_do_usuario>")

# Exemplo de busca
#ret = search_user("sAMAccountName", "userAD1", "DC=AD-DEMO,DC=local", 'AD-DEMO\\userAD01', "Passw0rd!")
#print(ret)

#if ret:
#    print(f'{ret[0]}')
#    print(f"{ret[0]['distinguishedName']}")
#    retorno = forgot_password(<usuario>, "<nova_senha>")
#    retorno = forgot_password(ret[0], "novas3nh@!")

#    retorno = change_password(<DistinguishedName>, "<senha_atual>", "<nova_senha>",  '<usuario_do_dominio>')
#    retorno = change_password(ret[0]['distinguishedName'], "Passw0rd!", "Passw0rd!Nov0",  'userAD1@AD-DEMO.local')
#    print(f'{retorno}')
