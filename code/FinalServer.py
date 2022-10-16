# Name : Madan Gopal
# Roll No : 20BCS122


import random
import socket
import pickle
from lib import *
import random
# symmetric key algorithm for encrypting message
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


def encrypt(pk, plaintext):
    # Unpack the key into it's components
    key, n = pk
    # Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [pow(ord(char), key, n) for char in plaintext]
    # Return the array of bytes
    return cipher


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
    # server program
    LOCALHOST = "127.0.0.1"
    PORT = 8080

    # creating the socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # binding the socket to port
    server.bind((LOCALHOST, PORT))

    # start listening for clients
    server.listen(5)
    p = int(input(" - Enter a prime number (17, 19, 23, etc): "))
    q = int(input(" - Enter another prime number (Not one you entered above): "))

    print(" - Generating your public / private key-pairs now . . .")

    public, private = generate_key_pair(p, q)

    print(" - Your public key is ", public, " and your private key is ", private)
    print("Server Started\n")
    print("Waiting for client request...\n")
    clientConnection, clientAddress = server.accept()
    print("Connected client :", clientAddress)
    # in_data = clientConnection.recv(1024)
    # print(in_data.decode())
    # print("\n")
    private_key = int2bits(random.randint(1, pow(2, 128)))
    data = clientConnection.recv(1024)
    clientKey = pickle.loads(data)
    print("Public key of client : ", clientKey)
    servPublicKey = pickle.dumps(public)
    clientConnection.send(servPublicKey)
    data = clientConnection.recv(1024)
    emsg = pickle.loads(data)
    emsg = decrypt(private, emsg)
    clientPrivateKey = emsg

    # print("Client private key for message : ", clientPrivateKey)
    # ePrivateKey = int(private_key, 2)
    # ePrivateKey = str(ePrivateKey)
    ePrivateKey = private_key
    ePrivateKey = encrypt(clientKey, ePrivateKey)
    emsg = pickle.dumps(ePrivateKey)
    clientConnection.send(emsg)
    msg = clientConnection.recv(1024)
    print(msg.decode("utf-8"))
    msg = ''
    while True:
        in_data = input("Enter message for client : ")
        while(len(in_data) != 8):
            print("Length of message must be 8 characters !")
            in_data = input("Enter message for client : ")
        data = in_data
        mode = "e"
        # converting string to bits
        data = str_to_bits(data)
        
        #encrypting the message 
        result = idea(data, private_key, mode)
        #sending the message to client
        clientConnection.send(bytes(result, "utf-8"))
        if(in_data == "good bye"):
            break

        # receiving the message from client
        msgRecv = clientConnection.recv(1024)
        msgRecv = msgRecv.decode("utf-8")
        mode = "d"
        data = msgRecv

        #function for decrypting the message
        result = idea(data, clientPrivateKey, mode)

        # converting binary string to string
        result = decode_binary_string(result)
        print("From Client : ", result)
        if(result == "good bye"):
            break

    clientConnection.close()
    print(" ")
    print("======================== END =============================")
    print("==========================================================")