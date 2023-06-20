import base32hex
import hashlib
from Crypto.Cipher import DES
password = "Password"
salt = '\x28\xAB\xBC\xCD\xDE\xEF\x00\x33'
key = password + salt
m = hashlib.md5(key)
key = m.digest()
(dk, iv) =(key[:8], key[8:])
crypter = DES.new(dk, DES.MODE_CBC, iv)
encrypted_string='UH562EGM8RCHHTOUC5CTRS59OG======'
print("The ecrypted string is : ",encrypted_string)
encrypted_string=base32hex.b32decode(encrypted_string)
decrypted_string = crypter.decrypt(encrypted_string)
print("The decrypted string is : ",decrypted_string)