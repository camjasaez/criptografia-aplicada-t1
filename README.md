# Criptografía Asimétrica y Funciones de Hashing

**Tarea 1 Criptografía Aplicada**

## Integrantes

- Camilo Saez Garrido
- Vicente Aguilera Arias

## Requisitos

- `python 3.9 `
- `pip 22`

## Instrucciones de uso

- Crea un entorno virtual con el siguiente comando:

```bash
python -m venv venv
```

- Activamos el entorno virtual:

```bash
source venv/bin/activate
```

- Instalamos las dependencias necesarias para ejecutar el programa:

```bash
pip install -r requirements.txt
```

**Para ejecutar los programas, se debe ejecutar el siguiente comando en la terminal**:

- Para el ejercicio 1:

  ```bash
  python key_gen.py
  ```

  - Se creara una carpeta llamada `/llaves` donde se guardaran las llaves generadas.
  - Se puede ingresar el nombre de la llave a generar, si no se ingresa nada o apreta solo enter, se generara una llave con el nombre `Alice` y `Bob` por defecto.

- Para el ejercicio 2:

  ```bash
  python exchange_msg.py
  ```

  - Se ingresa un texto a cifrar

- Para el ejercicio 3:
  ```bash
  python decipher.py
  ```
  - Se verifica el mensaje recibido y se desencripta
