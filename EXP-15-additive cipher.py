import string
alphabet = string.ascii_lowercase
def frequency_analysis(text):
    frequencies = [0] * 26
    for letter in text.lower():
        if letter in alphabet:
            frequencies[alphabet.index(letter)] += 1
    return frequencies
def decrypt(ciphertext, key):
    plaintext = ''
    for i in range(len(ciphertext)):
        if ciphertext[i] in alphabet:
            plaintext += alphabet[(alphabet.index(ciphertext[i]) - key) % 26]
        else:
            plaintext += ciphertext[i]
    return plaintext
ciphertext = input("Enter ciphertext: ")
frequencies = frequency_analysis(ciphertext)
most_common_index = frequencies.index(max(frequencies))
key = (most_common_index - alphabet.index('e')) % 26
plaintext = decrypt(ciphertext, key)
print("The most likely plaintext is: ", plaintext)
num_plaintexts = int(input("Enter the number of possible plaintexts to display: "))
plaintexts = []
for k in range(26):
    plaintext = decrypt(ciphertext, k)
    frequencies = frequency_analysis(plaintext)
    plaintexts.append((plaintext, frequencies))
plaintexts.sort(key=lambda x: max(x[1]), reverse=True)
for i in range(num_plaintexts):
    print(f"Plaintext #{i+1}:", plaintexts[i][0])