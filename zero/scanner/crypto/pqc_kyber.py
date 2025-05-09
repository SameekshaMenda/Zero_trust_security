import oqs

def pqc_encrypt_decrypt(message):
    with oqs.KeyEncapsulation("Kyber512") as server:
        public_key = server.generate_keypair()
        
        # Simulate client encapsulation
        ciphertext, shared_secret_client = oqs.KeyEncapsulation("Kyber512").encap_secret(public_key)
        
        # Server decapsulates
        shared_secret_server = server.decap_secret(ciphertext)

        return {
            "public_key": public_key.hex(),
            "ciphertext": ciphertext.hex(),
            "shared_secret": shared_secret_server.hex(),
            "original_message": message
        }
