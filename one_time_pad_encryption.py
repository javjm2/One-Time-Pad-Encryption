import string
import random

KEY = []


def create_key(user_input):
    plain_text = user_input.replace(' ', '')

    for letter in plain_text:
        KEY.append(random.choice(string.ascii_letters + '0123456789'))
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
    print('Encryption in progress' + '\n')
    plain_text_value, key_value = plain_text, key
    cipher_text_binary = []

    for i, j in zip(plain_text_value, key_value):
        if int(i) ^ int(j):
            cipher_text_binary.append('1')
        else:
            cipher_text_binary.append('0')
    cipher_text_binary = ''.join(cipher_text_binary)
    return cipher_text_binary


def decrypt(cipher_text, key):
    # Here I'm performing a bitwise XOR operation on the cipher text and the key to decrypt the data
    print('Decryption in progress' + '\n')
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
    user_input = input('Enter value' + '\n')
    plain_text, key = create_key(user_input)
    plain_text_binary, key_binary = convert_plain_text_and_key(plain_text, key)
    cipher_text_binary = encrypt(plain_text_binary, key_binary)

    print(f'Cipher text of the user input "{user_input}": "{binary_to_string(cipher_text_binary)}"')
    decrypted_plain_text_binary = decrypt(cipher_text_binary, key_binary)
    if decrypted_plain_text_binary == plain_text_binary:
        print(user_input)
    else:
        raise Exception('The plain text message and the decrypted version of that message do not match')


if __name__ == "__main__":
    main()
