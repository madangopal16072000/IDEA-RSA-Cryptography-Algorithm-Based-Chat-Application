from cv2 import getOptimalDFTSize


# Name : Madan Gopal 
# Roll NO : 20BCS122

import random
import socket
import pickle
from lib import *
import random
import sys


def idea(block, key, mode):
    binaryData = block
    X = split_into_x_parts_of_y(binaryData, 4, M)

    Z = generate_subkeys(key)
    if mode == 'd':
        Z = generate_decrypt_keys(Z) 

    #  8 Rounds
    for i in range(8):
    # variable names will follow the fourteen-step method 
    # described in the document
        multiplier = i * 6

        one = m_mul(X[0], Z[multiplier + 0])
        two = m_sum(X[1], Z[multiplier + 1])
        three = m_sum(X[2], Z[multiplier + 2])
        four = m_mul(X[3], Z[multiplier + 3])

        five = XOR(one, three)
        six = XOR(two, four)
        seven = m_mul(five, Z[multiplier + 4])
        eight = m_sum(six, seven)
        nine = m_mul(eight, Z[multiplier + 5])
        ten = m_sum(seven, nine)
        eleven = XOR(one, nine)
        twelve = XOR(three, nine)
        thirteen = XOR(two, ten)
        fourteen = XOR(four, ten)
        if i == 7:
            X = [eleven, thirteen, twelve, fourteen]
        else:
            X = [eleven, twelve, thirteen, fourteen]

    # Output pre-processing (half-round)    
    X[0] = m_mul(X[0], Z[48])
    X[1] = m_sum(X[1], Z[49])
    X[2] = m_sum(X[2], Z[50])
    X[3] = m_mul(X[3], Z[51])
    
    return ''.join(X)
'''
Euclid's algorithm for determining the greatest common divisor
Use iteration to make it faster for larger integers
'''


def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a


'''
Euclid's extended algorithm for finding the multiplicative inverse of two numbers
'''


def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi//e
        temp2 = temp_phi - temp1 * e
        temp_phi = e
        e = temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if temp_phi == 1:
        return d + phi


'''
Tests to see if a number is prime.
'''


def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

# function for generating public and private assymetric keys 
def generate_key_pair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    # n = pq
    n = p * q

    # Phi is the totient of n
    phi = (p-1) * (q-1)

    # Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    # Use Euclid's Algorithm to verify that e and phi(n) are coprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)

    # Use Extended Euclid's Algorithm to generate the private key
    d = multiplicative_inverse(e, phi)

    # Return public and private key_pair
    # Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))


#function for encrypting keys using RSA algorithm it takes private key and plaintext as input
def encrypt(pk, plaintext):
    # Unpack the key into it's components
    key, n = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [pow(ord(char), key, n) for char in plaintext]
    # Return the array of bytes
    return cipher

# function for decrypting ciphertext
def decrypt(pk, ciphertext):
    # Unpack the key into its components
    key, n = pk
    # Generate the plaintext based on the ciphertext and key using a^b mod m
    aux = [str(pow(char, key, n)) for char in ciphertext]
    # Return the array of bytes as a string
    plain = [chr(int(char2)) for char2 in aux]
    return ''.join(plain)


if __name__ == '__main__':
    '''
    Detect if the script is being run directly by the user
    '''
    print("==========================================================")
    print("============ IDEA & RSA Encryptor / Decrypter ============")
    print(" ")
    print("Name : Madan Gopal")
    print("Roll no : 20BCS122")
    print(" ")
    

    
    # Client socket programming programming
    SERVER = "127.0.0.1"
    PORT = 8080

    # creating socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connecting the server
    client.connect((SERVER, PORT))

    p = int(input(" - Enter a prime number (17, 19, 23, etc): "))
    q = int(input(" - Enter another prime number (Not one you entered above): "))

    print(" - Generating your public / private key-pairs now . . .")

    public, private = generate_key_pair(p, q)

    print(" - Your public key is ", public, " and your private key is ", private)

    private_key = int2bits(random.randint(1, pow(2, 128)))
    # client.sendall(bytes("This from client", "utf-8"))
    clientPublicKey = pickle.dumps(public)
    client.send(clientPublicKey)
    data = client.recv(1024)
    servKey = pickle.loads(data)
    print("Server Public Key : ", servKey)
    # clientPrivateKey = int(private_key, 2)
    # clientPrivateKey = str(clientPrivateKey)
    clientPrivateKey = private_key
    emsg = encrypt(servKey, clientPrivateKey)
    msgToSend = pickle.dumps(emsg)
    client.send(msgToSend)

    data = client.recv(1024)
    emsg = pickle.loads(data)
    emsg = decrypt(private, emsg)
    servPrivateKey = emsg
    # print("private key of server for message : ", servPrivateKey)

    client.send("Enter good bye to exit!".encode())
    print("Enter good bye to exit!")
    while True:

        # recieving message from server
        in_data = client.recv(1024)
        # converting message to bytes form
        in_data = in_data.decode('utf-8')
        mode = "d"
        data = in_data

        # decrypting the message
        result = idea(data, servPrivateKey, mode)

        # converting binary string to string
        result = decode_binary_string(result)
        print("From Server : ", result)
        if(result == "good bye"):
            break

        data = input("Enter mesage for server : ")
        while(len(data) != 8):
            print("Length of message must be 8 characters!")
            data = input("Enter message for server : ")
        msgToSend = data
        mode = "e"
        # changin string to bits
        data = str_to_bits(msgToSend)

        # encrypting the message
        result = idea(data, private_key, mode)

        client.send(bytes(result, "utf-8"))
        if(data == "good bye"):
            break
    client.close()
    print(" ")
    print("====================== END ===============================")
    print("==========================================================")
