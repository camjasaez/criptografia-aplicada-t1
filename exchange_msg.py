# El segundo programa debe permitir que dos personas intercambien mensajes cifrados. Por simplicidad piense que usted es  Alice desee enviar un mensaje a su compañero Bob:
# Solicitar un texto desde teclado a Alice,
# Lee llave privada de Alice y llave pública de Bob
# Firma texto plano con llave privada de Alice. Escriba firma en un archivo  (Por ejemplo "Signature_Alice. sig")
# Genera una llave AES y cifra texto plano en modo CBC con AES (no cifre la firma) y escribe texto cifrado en un archivo. También escribe vector IV en un archivo (IV.iv)
# Cifra la llave AES con llave pública de Bob y almacena llave AES cifrada en otro archivo. (Ejemplo llave_AES_cifrada.key)

def main():
    print("=> Iniciando ejecucion de exchange_msg" + "\n")


if __name__ == "__main__":
    main()