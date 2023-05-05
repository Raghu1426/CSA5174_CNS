def generate_cipher(keyword):
    keyword = ''.join(sorted(set(keyword), key=keyword.index))
    cipher = keyword + ''.join(c for c in 'abcdefghijklmnopqrstuvwxyz' if c not in keyword)
    return cipher
def encrypt(plaintext, cipher):
    ciphertext = ''
    for c in plaintext:
        if c.isalpha():
            ciphertext += cipher[ord(c.lower()) - ord('a')].upper()
        else:
            ciphertext += c
    return ciphertext
def decrypt(ciphertext, cipher):
    plaintext = ''
    for c in ciphertext:
        if c.isalpha():
            plaintext += chr(cipher.index(c.lower()) + ord('a'))
        else:
            plaintext += c
    return plaintext
keyword = 'CIPHER'
cipher = generate_cipher(keyword)
print('Cipher sequence:', cipher)
plaintext = 'the quick brown fox jumps over the lazy dog'
ciphertext = encrypt(plaintext, cipher)
print('Ciphertext:', ciphertext)
decrypted_text = decrypt(ciphertext, cipher)
print('Decrypted plaintext:', decrypted_text)
