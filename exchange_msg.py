"""
Este programa permite que dos personas intercambien mensajes cifrados.
"""
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def solicitar_texto():
    """
    Esta función solicita al usuario ingresar un texto desde el teclado.

    :return: El texto ingresado por el usuario.
    :rtype: Str
    """
    texto = input("Ingrese el texto: ").encode()
    return texto


def leer_llave_privada(nombre_archivo):
    """
    Esta función lee una llave privada RSA desde un archivo PEM.

    :param nombre_archivo: El nombre del archivo que contiene la llave privada.
    :type nombre_archivo: Str

    :return: La llave privada leída.
    :rtype: RSAPrivateKey
    """
    ruta_archivo = os.path.join("llaves", nombre_archivo)
    with open(ruta_archivo, "rb") as i:
        return serialization.load_pem_private_key(
            i.read(),
            password=None
        )


def leer_llave_publica(nombre_archivo):
    """
    Esta función lee una llave pública RSA desde un archivo PEM.

    :param nombre_archivo: El nombre del archivo que contiene la llave pública.
    :type nombre_archivo: Str

    :return: La llave pública leída.
    :rtype: RSAPublicKey
    """
    ruta_archivo = os.path.join("llaves", nombre_archivo)
    with open(ruta_archivo, "rb") as i:
        return serialization.load_pem_public_key(i.read())


def firmar_texto(texto, llave_privada, nombre_archivo):
    """
    Esta función firma un texto utilizando una llave privada y guarda la firma en un archivo.

    :param texto: El texto a firmar.
    :type texto: Str

    :param llave_privada: La llave privada utilizada para firmar.
    :type llave_privada: RSAPrivateKey

    :param nombre_archivo: El nombre del archivo donde se guardará la firma.
    :type nombre_archivo: Str

    :return: None
    """
    ruta_archivo = os.path.join("cifrado", nombre_archivo)
    firma = llave_privada.sign(
        texto,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    with open(ruta_archivo, "wb") as i:
        i.write(firma)


def cifrar_texto(texto, llave_aes, nombre_archivo_texto_cifrado, nombre_archivo_iv):
    """
    Esta función cifra un texto en modo CBC utilizando una llave AES 
    y guarda el texto cifrado y el IV en archivos.

    :param texto: El texto a cifrar.
    :type texto: Str

    :param llave_aes: La llave AES utilizada para el cifrado.
    :type llave_aes: bytes

    :param nombre_archivo_texto_cifrado: El nombre del archivo donde se guardará el texto cifrado.
    :type nombre_archivo_texto_cifrado: Str

    :param nombre_archivo_iv: El nombre del archivo donde se guardará el IV.
    :type nombre_archivo_iv: Str

    :return: None
    """
    vector = os.urandom(16)  # Generar un IV aleatorio

    # Rellenar el texto con PKCS7
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    texto_rellenado = padder.update(texto) + padder.finalize()

    # Cifrar el texto rellenado
    cifrador = Cipher(algorithms.AES(llave_aes), modes.CBC(vector))
    cifrador = cifrador.encryptor()
    texto_cifrado = cifrador.update(texto_rellenado) + cifrador.finalize()

    ruta_archivo_texto_cifrado = os.path.join("cifrado", nombre_archivo_texto_cifrado)
    ruta_archivo_iv = os.path.join("cifrado", nombre_archivo_iv)

    with open(ruta_archivo_texto_cifrado, "wb") as i:
        i.write(texto_cifrado)

    with open(ruta_archivo_iv, "wb") as i:
        i.write(vector)


def cifrar_llave_aes_con_llave_publica(llave_aes, llave_publica, nombre_archivo):
    """
    Esta función cifra una llave AES utilizando la llave pública 
    de Bob y guarda la llave cifrada en un archivo.

    :param llave_aes: La llave AES a cifrar.
    :type llave_aes: bytes

    :param llave_publica: La llave pública de Bob.
    :type llave_publica: RSAPublicKey

    :param nombre_archivo: El nombre del archivo donde se guardará la llave AES cifrada.
    :type nombre_archivo: Str

    :return: None
    """
    ruta_archivo = os.path.join("cifrado", nombre_archivo)
    llave_aes_cifrada = llave_publica.encrypt(
        llave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(ruta_archivo, "wb") as i:
        i.write(llave_aes_cifrada)


def main():
    """
    Función principal que ejecuta el intercambio de mensajes cifrados.

    Realiza los siguientes pasos:
    1. Crea una carpeta para guardar los archivos cifrados.
    2. Solicita un texto desde el teclado a Alice.
    3. Lee la llave privada de Alice y la llave pública de Bob.
    4. Firma el texto con la llave privada de Alice y guarda la firma en un archivo.
    5. Genera una llave AES aleatoria, cifra el texto en modo 
    CBC y guarda el texto cifrado y el IV en archivos.
    6. Cifra la llave AES con la llave pública de Bob y guarda la llave cifrada en un archivo.
    7. Imprime un mensaje indicando la finalización del intercambio de mensajes.

    :return: None
    """
    print("=> Iniciando ejecucion de exchange_msg" + "\n")

    # Crear carpeta para guardar archivos
    if not os.path.exists("cifrado"):
        print('* => Creando carpeta "/cifrado *" ...' + "\n")
        os.makedirs("cifrado")

    # Punto 1: Solicitar un texto desde teclado a Alice
    texto_plano = solicitar_texto()

    # Punto 2: Leer llave privada de Alice y llave pública de Bob
    llave_privada_alice = leer_llave_privada("llave_privada_Alice.pem")
    llave_publica_bob = leer_llave_publica("llave_publica_Bob.pub")

    # Punto 3: Firmar texto con la llave privada de Alice
    nombre_archivo_firma_alice = "Signature_Alice.sig"
    firmar_texto(texto_plano, llave_privada_alice, nombre_archivo_firma_alice)

    # Punto 4: Generar una llave AES, cifrar el texto en
    # modo CBC y escribir texto cifrado e IV en archivos
    llave_aes = os.urandom(32)  # Generar una llave AES aleatoria de 256 bits

    nombre_archivo_texto_cifrado = "texto_cifrado.txt"
    nombre_archivo_iv = "IV.iv"
    cifrar_texto(texto_plano, llave_aes, nombre_archivo_texto_cifrado, nombre_archivo_iv)

    # Punto 5: Cifrar la llave AES con la llave pública de Bob
    # y almacenar la llave AES cifrada en un archivo
    nombre_archivo_llave_aes_cifrada = "llave_AES_cifrada.key"
    cifrar_llave_aes_con_llave_publica(llave_aes, llave_publica_bob,
                                       nombre_archivo_llave_aes_cifrada)

    print("=> Fin de ejecucion de exchange_msg" + "\n")


if __name__ == "__main__":
    main()
