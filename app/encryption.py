from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

def hash_with_salt(password, salt=None):
    """ Genera un hash de la contraseña con un salt. """
    if salt is None:
        salt = get_random_bytes(16)  # Genera un salt aleatorio de 16 bytes
    password_bytes = password.encode()
    hash_obj = SHA256.new()
    hash_obj.update(password_bytes + salt)
    
    return hash_obj.hexdigest(), salt.hex()  # Devuelve el hash y el salt en formato hexadecimal

def verify_password(stored_hash, stored_salt, provided_password):
    salt_bytes = bytes.fromhex(stored_salt)  # Convertir el salt de hex a bytes
    new_hash, _ = hash_with_salt(provided_password, salt_bytes)

    return new_hash == stored_hash  # Comparar hashes directamente
