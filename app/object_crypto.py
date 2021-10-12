import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad


class AESCipher(object):

    def encrypt(self, data, key=None, nonce=None):
        header = b''
        if key is None:
            key = get_random_bytes(32)

        if nonce is None:
            cipher = AES.new(key, AES.MODE_GCM)
        else:
            cipher = AES.new(key=key, nonce=nonce, mode=AES.MODE_GCM)

        cipher.update(header)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        json_k = [ 'nonce', 'header', 'tag', 'key']
        json_v = [ b64encode(x).decode('utf-8') for x in [cipher.nonce, header, tag, key]]
        result = dict(zip(json_k, json_v))
        # Output tuple of parameters dictionary, ciphertext
        return result, ciphertext
        
    def decrypt(self, json_input, ciphertext):
        try:
            json_k = [ 'nonce', 'tag', 'key']
            jv = {k: b64decode(json_input[k]) for k in json_k}
            header = b''
            cipher = AES.new(jv['key'], AES.MODE_GCM, nonce=jv['nonce'])
            cipher.update(header)
            plaintext = cipher.decrypt_and_verify(ciphertext, jv['tag'])
            return plaintext
        except (ValueError, KeyError) as e:
            print("Incorrect decryption: " + str(e))
