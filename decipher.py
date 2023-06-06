from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


def descifrar_llave_aes_cifrada(llave_aes_cifrada, llave_privada_bob):
    llave_aes = llave_privada_bob.decrypt(
        llave_aes_cifrada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return llave_aes


def descifrar_texto_cifrado(texto_cifrado, llave_aes, iv):
    # descifrador = Cipher(algorithms.AES(llave_aes), modes.CBC(iv)).decryptor()
    # texto_descifrado = descifrador.update(texto_cifrado) + descifrador.finalize()
    # return texto_descifrado

    cipher = Cipher(algorithms.AES(llave_aes), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(texto_cifrado) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def verificar_firma(texto, firma, llave_publica_alice):
    try:
        llave_publica_alice.verify(
            firma,
            texto,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False


def main():

    # Cargar llave RSA pública
    with open("llaves/llave_publica_Alice.pub", "rb") as f:
        llave_publica_alice = serialization.load_pem_public_key(
            f.read()
        )

    # Cargar llave RSA privada
    with open("llaves/llave_privada_Bob.pem", "rb") as f:
        llave_privada_bob = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    # Punto 1: Descifrar llave AES cifrada con llave privada de Bob
    with open("cifrado/llave_AES_cifrada.key", "rb") as f:
        llave_aes_cifrada = f.read()

    llave_aes = descifrar_llave_aes_cifrada(llave_aes_cifrada, llave_privada_bob)

    # Punto 2: Desencriptar texto cifrado de Alice con llave AES y IV
    with open("cifrado/texto_cifrado.txt", "rb") as f:
        texto_cifrado = f.read()
    with open("cifrado/IV.iv", "rb") as f:
        iv = f.read()
    texto_descifrado = descifrar_texto_cifrado(texto_cifrado, llave_aes, iv)

    print("Texto descifrado: ", texto_descifrado)

    # Punto 3: Verificar la firma y genuinidad del mensaje
    with open("cifrado/Signature_Alice.sig", "rb") as f:
        firma = f.read()


    if verificar_firma(texto_descifrado, firma, llave_publica_alice):
        print("La firma es válida.")
        print("El mensaje es genuino.")
        print("Contenido del texto plano:")
        print(texto_descifrado.decode())
    else:
        print("La firma es inválida. El mensaje ha sido alterado o no proviene de Alice.")


if __name__ == "__main__":
    main()
