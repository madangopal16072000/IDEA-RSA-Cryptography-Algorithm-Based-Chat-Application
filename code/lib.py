# Name : Madan Gopal
# Roll No : 20BCS122




import binascii
M = 16
Num = pow(2, M)
Num_plus_1 = Num + 1


# function for calculating XOR
def XOR(a, b):
    if len(a) != len(b):
        raise Exception('XOR operator unequal sizes between inputs a={} b={}'.format(len(a), len(b))) 

    result = ""
    for i in range(len(a)):
        result += '1' if a[i] != b[i] else '0'
    
    return result

#function for left shifting the binary string

def circular_left_shift(binString, k):
    res = binString
    for i in range(k):
        tmp = res[0]
        res = res[1:] + tmp
    return res

#function for generating subkeys from main keys
def generate_subkeys(data):
    if len(data) != 128:
        raise Exception('generate keys function requires an input of 128 bits, but received {}'.format(len(data)))
    

    keys = []
    for i in range(7):
        subkeys = split_into_x_parts_of_y(data, 8, 16)
        keys += subkeys
        data = circular_left_shift(data, 25)
    
    return keys[:-4]


# function for splition data into parts
def split_into_x_parts_of_y(data, x, y):
    res = []
    for i in range(x):
        multiplier = y * i
        start = 0 + multiplier
        stop = y + multiplier
        res.append(data[start:stop])
    return res

# function for generating decrypt keys
def generate_decrypt_keys(keys):
    decrypt_keys = []
    for i in range(8):
        step = i * 6
        lower_index = 46 - step
        
        decrypt_keys.append(m_mul_inv(keys[lower_index + 2], Num_plus_1))

        tmp1 = 4
        tmp2 = 3
        if i == 0:
            tmp1 = 3
            tmp2 = 4

        decrypt_keys.append(m_sum_inv(keys[lower_index + tmp1], Num))
        decrypt_keys.append(m_sum_inv(keys[lower_index + tmp2], Num))
        
        decrypt_keys.append(m_mul_inv(keys[lower_index + 5], Num_plus_1))
        decrypt_keys.append(keys[lower_index])
        decrypt_keys.append(keys[lower_index + 1])

    decrypt_keys.append(m_mul_inv(keys[0], Num_plus_1))
    decrypt_keys.append(m_sum_inv(keys[1], Num))
    decrypt_keys.append(m_sum_inv(keys[2], Num))
    decrypt_keys.append(m_mul_inv(keys[3], Num_plus_1))

    return decrypt_keys


# function for finding multiplicative invers
def m_mul_inv(a, m):
    m0 = m 
    y = 0
    x = 1
    a = int(a, 2)
    if (m == 1) : 
        return 0

    while (a > 1) : 

        # q is quotient 
        q = a // m 
        t = m 

        # m is remainder now, process 
        # same as Euclid's algo 
        m = a % m 
        a = t 
        t = y 

        # Update x and y 
        y = x - q * y 
        x = t 

    # Make x positive 
    if (x < 0) : 
        x = x + m0 

    bits = bin(x)[2:]
    return bits.zfill(16)


#function for finding additive invers
def m_sum_inv(a, m):
    res = m - int(a, 2)
    bits = bin(res)[2:]
    return bits.zfill(16)

# function for finding modular multiplication
def m_mul(a, b):
    a = int(a, 2) 
    b = int(b, 2)
    res = (a * b) % Num_plus_1
    bits = bin(res)[2:]
    return bits.zfill(16)


# function for finding modular addition
def m_sum(a, b):
    a = int(a, 2) 
    b = int(b, 2)
    res = (a + b) % Num
    bits = bin(res)[2:]
    return bits.zfill(16)

# function for converting integers to string
def int2bits(val):
    bits = bin(val)[2:]
    return bits.zfill(128)


# function for converting binary string to string
def decode_binary_string(s):
    return ''.join(chr(int(s[i*8:i*8+8],2)) for i in range(len(s)//8))

# function for converting string to bits
def str_to_bits(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
    bits = bits.zfill(8 * ((len(bits) + 7) // 8))
    return bits


if __name__ == '__main__':

    assert(circular_left_shift("111100001111000011110000", 5) == "000111100001111000011110")
    assert(XOR("1001", "0111") == "1110")
    assert(m_mul("10", "10") == "0000000000000100")
    assert(m_mul("11111111111111111", "10") == "1111111111111011")
    assert(m_mul_inv("0001", 2) == 1)
    assert(m_mul_inv("00000111", 87) == 25)