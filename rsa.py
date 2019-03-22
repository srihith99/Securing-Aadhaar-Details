import random
from Crypto.Util import number
import os

'''
Euclid's algorithm for determining the greatest common divisor
Use iteration to make it faster for larger integers
'''
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def is_prime(num, test_count):
    if num == 1:
        return False
    if test_count >= num:
        test_count = num - 1
    for x in range(test_count):
        val = random.randint(1, num - 1)
        if pow(val, num-1, num) != 1:
            return False
    return True

def generate_big_prime(n):
    found_prime = False
    while not found_prime:
        p = random.randint(2*(n-1), 2*n)
        if is_prime(p, 1000):
            return p
def generate_keypair(p, q):
    '''if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')'''
    #n = pq
    n = p * q

    #Phi is the totient of n
    phi = (p-1) * (q-1)

    #Choose an integer e such that e and phi(n) are coprime
    e = random.randrange(1, phi)

    #Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    print(e)

    #Use Extended Euclid's Algorithm to generate the private key
    d = modinv(e, phi)
    
    #Return public and private keypair
    #Public key is (e, n) and private key is (d, n)
    return ((e, n), (d, n))

def encrypt(pk, plaintext):
    #Unpack the key into it's components
    key, n = pk
    #Convert each letter in the plaintext to numbers based on the character using a^b mod m
    cipher = [(ord(char) ** key) % n for char in plaintext]
    #Return the array of bytes
    return cipher

def decrypt(pk, ciphertext):
    #Unpack the key into its components
    key, n = pk
    #Generate the plaintext based on the ciphertext and key using a^b mod m
    plain = [chr((char ** key) % n) for char in ciphertext]
    #Return the array of bytes as a string
    return ''.join(plain)
    

print ("RSA Encrypter/ Decrypter")
primeNum1 = int(input("Enter a prime number (17, 19, 23, etc): "))
primeNum2 = int(input("Enter another prime number (Not one you entered above): "))
n_length = 2048
#primeNum1 = generate_big_prime(n_length)
#primeNum2 = generate_big_prime(n_length)
while primeNum1 == primeNum2:
    primeNum2 = generate_big_prime(n_length)
print ("Generating your public/private keypairs now . . .")
public, private = generate_keypair(primeNum1, primeNum2)
print ("Your public key is ", public ," and your private key is ", private)
message = input("Enter a message to encrypt with your private key: ")
encrypted_msg = encrypt(private, message)
print ("Your encrypted message is: ")
print (''.join(map(lambda x: str(x), encrypted_msg)))
print ("Decrypting message with public key ", public ," . . .")
print ("Your message is:")

    
print (decrypt(public, encrypted_msg))