import json

def get_decrypted_api_key(json_file, keyword):
    with open(json_file, 'r') as file:
        data = json.load(file)

    api_key = data["encrypted_key"]

    decrypted_key = decrypt_key(api_key, keyword)
    return decrypted_key

def decrypt_key(encrypted_key, keyword):
    decrypted_key = ""
    keyword_index = 0

    for char in encrypted_key:
        if char.isalpha():
          
            ascii_offset = ord('A') if char.isupper() else ord('a')
            key_char = keyword[keyword_index % len(keyword)]
            key_offset = ord(key_char.upper()) - ord('A')
            decrypted_char = chr((ord(char) - ascii_offset - key_offset) % 26 + ascii_offset)
            decrypted_key += decrypted_char
            keyword_index += 1
        else:
            decrypted_key += char

    return decrypted_key

