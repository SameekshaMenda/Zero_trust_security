def quantum_encrypt(message):
    """
    Simulates quantum-safe encryption and decryption of a message.
    
    Parameters:
        message (str): The plain text message to encrypt.
    
    Returns:
        tuple: (encrypted_text, decrypted_text)
    """
    # Simulate encryption: Shift characters by 3 positions (toy example)
    encrypted = ''.join(chr((ord(c) + 3) % 256) for c in message)

    # Simulate decryption: Reverse the shift
    decrypted = ''.join(chr((ord(c) - 3) % 256) for c in encrypted)

    return encrypted, decrypted
