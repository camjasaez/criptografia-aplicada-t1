from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import os

# El primer programa debe crear un par de llaves asimétricas RSA para ambos integrantes del grupo.
# Las parejas de llaves deben ser almacenadas en un archivo formato PEM y etiquetadas con el nombre de su dueño.
# Ejemplo: llave_privada_Alice.key y llave_publica_Alice. key (de manera equivalente para Bob)
# Intercambien los archivos que contienen sus llaves públicas

# Documentacion utilizada:
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#generation


def generar_llaves():
    """
    Esta función genera una clave privada utilizando el algoritmo RSA.

    :return: Clave privada generada.
    :rtype: RSAPrivateKey
    """
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def guardar_llave_privada(llave_privada, nombre_archivo):
    """
    Esta función guarda una llave privada en un archivo.

    :param llave_privada: La llave privada a guardar.
    :type llave_privada: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey

    :param nombre_archivo: El nombre del archivo donde se guardará la llave privada.
    :type nombre_archivo: Str

    :return: None
    """
    ruta_archivo = os.path.join("llaves", nombre_archivo)
    with open(ruta_archivo, "wb") as f:
        f.write(
            llave_privada.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


# Guardamos las llaves en un archivo PEM
def guardar_llave_publica(llave_publica, nombre_archivo):
    """
    Esta función guarda una llave pública en un archivo.

    :param llave_publica: La llave pública a guardar.
    :type llave_publica: cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey

    :param nombre_archivo: El nombre del archivo donde se guardará la llave pública.
    :type nombre_archivo: str

    :return: None
    """
    ruta_archivo = os.path.join("llaves", nombre_archivo)
    with open(ruta_archivo, "wb") as f:
        f.write(
            llave_publica.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


# Generamos y guardamos las llaves para una persona
def generar_y_guardar_llaves(nombre_persona):
    """
    Esta función genera y guarda un par de llaves pública y privada RSA para una persona.

    :param nombre_persona: El nombre de la persona para la cual se generarán las llaves.
    :type nombre_persona: Str

    :return: None
    """
    # Generación de claves RSA
    llave_privada = generar_llaves()

    # Almacenamiento de la llave privada en un archivo PEM
    nombre_archivo_privada = f"llave_privada_{nombre_persona}.pem"
    guardar_llave_privada(llave_privada, nombre_archivo_privada)

    # Obtención de la llave pública
    llave_publica = llave_privada.public_key()

    # Almacenamiento de la llave pública en un archivo PEM
    nombre_archivo_publica = f"llave_publica_{nombre_persona}.pub"
    guardar_llave_publica(llave_publica, nombre_archivo_publica)


def main():
    """
    Función principal del programa.

    - Crea la carpeta "llaves" si no existe.
    - Genera y guarda llaves para Alice.
    - Genera y guarda llaves para Bob.

    :return: None
    """
    print("* => Iniciando ejecucion de key_gen *" + "\n")
    if not os.path.exists("llaves"):
        print('* => Creando carpeta "/llaves *" ...' + "\n")
        os.makedirs("llaves")

    nombre_default = "Alice"
    generar_y_guardar_llaves(nombre_default)

    nombre_default = "Bob"
    generar_y_guardar_llaves(nombre_default)

    print("* => Finalizando ejecucion de key_gen *" + "\n")


if __name__ == "__main__":
    main()
