"""
Este script descifra el mensaje enviado por Alice a Bob.
"""

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature


def descifrar_llave_aes_cifrada(llave_aes_cifrada, llave_privada_bob):
    """
    Esta función descifra una llave AES cifrada con la llave privada de Bob.

    :param llave_aes_cifrada: La llave AES cifrada.
    :type llave_aes_cifrada: bytes

    :param llave_privada_bob: La llave privada de Bob.
    :type llave_privada_bob: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey

    :return: La llave AES descifrada.
    :rtype: bytes
    """
    llave_aes = llave_privada_bob.decrypt(
        llave_aes_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return llave_aes


def descifrar_texto_cifrado(texto_cifrado, llave_aes, vector):
    """
    Esta función descifra un texto cifrado utilizando una llave AES y un vector.

    :param texto_cifrado: El texto cifrado.
    :type texto_cifrado: bytes

    :param llave_aes: La llave AES.
    :type llave_aes: bytes

    :param vector: El vector (Initialization Vector).
    :type vector: bytes

    :return: El texto descifrado.
    :rtype: bytes
    """
    cipher = Cipher(algorithms.AES(llave_aes), modes.CBC(vector))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(texto_cifrado) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext



def verificar_firma(texto, firma, llave_publica_alice):
    """
    Esta función verifica la firma de un texto utilizando la llave pública de Alice.

    :param texto: El texto original.
    :type texto: bytes

    :param firma: La firma a verificar.
    :type firma: bytes

    :param llave_publica_alice: La llave pública de Alice.
    :type llave_publica_alice: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey

    :return: True si la firma es válida, False en caso contrario.
    :rtype: bool
    """
    try:
        llave_publica_alice.verify(
            firma,
            texto,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def main():
    """
    Esta función es el punto de entrada principal del programa.

    Realiza los siguientes pasos:
    1. Cargar la llave RSA pública de Alice.
    2. Cargar la llave RSA privada de Bob.
    3. Descifrar la llave AES cifrada con la llave privada de Bob.
    4. Desencriptar el texto cifrado de Alice con la llave AES y el IV.
    5. Verificar la firma y genuinidad del mensaje.

    Imprime el resultado de la verificación y el contenido del texto descifrado.
    """
    # Cargar llave RSA pública
    with open("llaves/llave_publica_Alice.pub", "rb") as public_key_file:
        llave_publica_alice = serialization.load_pem_public_key(public_key_file.read())

    # Cargar llave RSA privada
    with open("llaves/llave_privada_Bob.pem", "rb") as private_key_file:
        llave_privada_bob = serialization.load_pem_private_key(
            private_key_file.read(), password=None
        )

    # Punto 1: Descifrar llave AES cifrada con llave privada de Bob
    with open("cifrado/llave_AES_cifrada.key", "rb") as key_file:
        llave_aes_cifrada = key_file.read()

    llave_aes = descifrar_llave_aes_cifrada(llave_aes_cifrada, llave_privada_bob)

    # Punto 2: Desencriptar texto cifrado de Alice con llave AES y IV
    with open("cifrado/texto_cifrado.txt", "rb") as ciphertext_file:
        texto_cifrado = ciphertext_file.read()
    with open("cifrado/IV.iv", "rb") as iv_file:
        vector = iv_file.read()
    texto_descifrado = descifrar_texto_cifrado(texto_cifrado, llave_aes, vector)

    print("Texto descifrado: ", texto_descifrado.decode())

    # Punto 3: Verificar la firma y genuinidad del mensaje
    with open("cifrado/Signature_Alice.sig", "rb") as signature_file:
        firma = signature_file.read()

    if verificar_firma(texto_descifrado, firma, llave_publica_alice):
        print("La firma es válida.")
        print("El mensaje es genuino.")
        print("Contenido del texto plano:")
        print(texto_descifrado.decode())
    else:
        print("La firma es inválida. El mensaje ha sido alterado o no proviene de Alice.")



if __name__ == "__main__":
    main()
