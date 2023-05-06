import numpy as np
key = np.array([[9, 4], [5, 7]])
plaintext = "meetmeattheusualplaceattenratherthaneightoclock"
if len(plaintext) % 2 != 0:
    plaintext += 'x'
plaintext_pairs = [plaintext[i:i+2] for i in range(0, len(plaintext), 2)]
plaintext_matrices = []
for pair in plaintext_pairs:
    plaintext_matrices.append(np.array([[ord(pair[0])-97], [ord(pair[1])-97]]))
ciphertext_pairs = []
for matrix in plaintext_matrices:
    result = key @ matrix % 26
    ciphertext_pairs.append(chr(result[0][0]+97) + chr(result[1][0]+97))
ciphertext = ''.join(ciphertext_pairs)
print("Plaintext: ", plaintext)
print("Ciphertext:", ciphertext)