import string
import random

KEY = []


def create_key():
    plain_text = input('Enter value' + '\n')
    plain_text = plain_text.replace(' ', '')

    for letter in plain_text:
        KEY.append(random.choice(string.ascii_letters))
    return plain_text, ''.join(KEY).replace(' ', '')


def convert_plain_text_and_key(plain_text, key):
    plain_text_list = []
    key_list = []

    for plain_character, key_character in zip(plain_text, key):
        p_binary = bin(ord(plain_character))
        k_binary = bin(ord(key_character))
        p_binary = p_binary.replace('b', '')
        k_binary = k_binary.replace('b', '')
        plain_text_list.append(p_binary)
        key_list.append(k_binary)

    plain_text = ''.join(plain_text_list)
    key = ''.join(key_list)
    return plain_text, key


def encrypt(plain_text, key):
    # Here I'm performing a bitwise XOR operation on the plain text and the key to encrypt the data
    print('Encrypting in progress' + '\n')
    plain_text_value, key_value = plain_text, key
    cipher_text = []

    for i, j in zip(plain_text_value, key_value):
        if int(i) ^ int(j):
            cipher_text.append('1')
        else:
            cipher_text.append('0')
    cipher_text = ''.join(cipher_text)
    return cipher_text


def decrypt(cipher_text, key):
    # Here I'm performing a bitwise XOR operation on the cipher text and the key to decrypt the data
    print('Decrypting in progress' + '\n')
    cipher_text_value, key_value = cipher_text, key
    plain_text = []

    for i, j in zip(cipher_text_value, key_value):
        if int(i) ^ int(j):
            plain_text.append('1')
        else:
            plain_text.append('0')
    plain_text = ''.join(plain_text)
    return plain_text


def binary_to_string(binaryString):
    return "".join([chr(int(binaryString[i:i + 8], 2)) for i in range(0, len(binaryString), 8)])


def main():
    plain_text, key = create_key()
    plain_text_binary, key_binary = convert_plain_text_and_key(plain_text, key)
    cipher_text_binary = encrypt(plain_text_binary, key_binary)
    print(f'One time pass cipher text with the string "{plain_text} - "' + cipher_text_binary)
    decrypted_plain_text_binary = decrypt(cipher_text_binary, key_binary)
    print(binary_to_string(decrypted_plain_text_binary))


if __name__ == "__main__":
    main()
