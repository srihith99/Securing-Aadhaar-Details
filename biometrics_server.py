#####################         SIH 2019        ###################
#####################    CIRCUIT BREAKERS     ####################
#####################    IITH HYDERABAD       ####################


#####################PYTHON CODE RUNNING SERVER PROOGRAMM ###################
##################### THIS SERVER CONNECTS TO BLOCK CHAIN TO HOLD TRACK OF TRANSACTIONS #############

##################### SERVER : FLASK PYTHON ########################################


###############   SERVER RUNNING ON 9000 ##############################



import json, requests, random, string, random, nexmo, base64, os, time
import hashlib as h
from flask import Flask,jsonify, request
from uuid import uuid4
import MySQLdb as sql
from Crypto.Cipher import AES
from Crypto.Util import number

# the block size for the cipher object; must be 16 per FIPS-197
BLOCK_SIZE = 16


primes = [ 100003,100019,100043,100049,100057,100069,100103,100109,100129,100151,
           100153,100169,100183,100189,100193,100207,100213,100237,100267,100271,
           100279,100291,100297,100313,100333,100343,100357,100361,100363,100379
         ]
n_length = 2048

all_fingerprints = []
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
    





app = Flask(__name__)
############ 4000 port request transaction blockchain ####################
node_address = "http://127.0.0.1:4000/"


######### 5000 port otp transaction blockchain
node_address_otp1 = "http://127.0.0.1:5000/"
node_address_otp2 = "http://127.0.0.1:5001/"
node_address_otp3 = "http://127.0.0.1:5002/"
#node_address_otp4 = "http://127.0.0.1:5003/"

node_address_otp = [node_address_otp1, node_address_otp2 , node_address_otp3]

# the character used for padding--with a block cipher such as AES, the value
# you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
# used to ensure that your value is always a multiple of BLOCK_SIZE
PADDING = '{'

# one-liner to sufficiently pad the text to be encrypted
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# one-liners to encrypt/encode and decrypt/decode a string
# encrypt with AES, encode with base64
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: (c.decrypt(bytes(base64.b64decode(e)))).rstrip(bytes(PADDING,'utf-8'))

# generate a random secret key
secret = os.urandom(BLOCK_SIZE)

# create a cipher object using the random secret


cipher = AES.new(secret)

################# DECRYPTION KEY ####################



#################  RSA ALGORITHM FOR UPDATING THE DETAILS #################
######### RETURNS A PAIR OF PRIRVATE AND PUBLIC KEY ###############
def rsa():
    global primes
    n1 = random.randint(0,len(primes)-1)
    n2 = random.randint(0,len(primes)-1)
    primeNum1 = primes[n1]
    primeNum2 = primes[n2]
    if primeNum1 == primeNum2:
        n2 = n2 + 1
    print("prime 1 " + str(primeNum1) + " and prime 2 " + str(primeNum2))
   
    public, private = generate_keypair(primeNum1, primeNum2)
    return public, private
    
    """
    print ("Your public key is ", public ," and your private key is ", private)
    
    message = input("Enter a message to encrypt with your private key: ")
    
    print ("Your encrypted message is: ")
    print (''.join(map(lambda x: str(x), encrypted_msg)))
    print ("Decrypting message with public key ", public ," . . .")
    print ("Your message is:")

        
    print (decrypt(public, encrypted_msg))
    """


def rsa_encryption(private_key , data):
    #Encrypting with private key
    encrypted_msg = encrypt(private_key, data)
    return ''.join(map(lambda x: str(x), encrypted_msg))

def rsa_decryption(public_key, encrypted_data ):
    # decrypt with RSA publci key 
    return decrypt(public_key, encrypted_data)


#### First transaction ....vendor requesting government aadhaar database for cross validation
### Hit following URL
@app.route('/check_details', methods= ['POST'])
def qr_transaction():
    print("Processing request..........")

    #proccessing request
    data_request = request.get_data()
    data_request = data_request.decode("utf-8").split("=")[1]
    data = json.loads(data_request)#convert to json
    mac_reference = data["from"] 
    #we store mac address of vendor temporarily in DB for inserting into BLOCKCHAIN records
    
    ############### From will be vendors device and we use MAC of device to identify the device
    mac = '5510204243' #setting our own MAC adress as we aare using Andriod phone, it doesnt allow
    #to extract MAC address as a result we are picking it and setting manually.
    ##### BUT MAC addreess could be extracted by packet sniffing 

    # Clearly vendor asking adhaar DB so transaction made to adhaar DB and to be inserted into block
    data['to'] = 'adhaarDB'
    data['timestamp'] = str(time.time())
    print("Time Stamp : " + data['timestamp'])
    data_request = str(data)
    ### our transaction data
    ### encryptiong our transaction- 

    ########### WE are encrypting only transaction with BLOCKCHAIn AES256 KEY ######################
    data_encrypted = EncodeAES(cipher, data_request).decode('utf-8') # data encrypted as string
    data_encrypted_json = { "encrypted_block" : data_encrypted } 

   
    """
                  STORED block in NODE looks like
                  DATA Encrypted
    {'uuid': '123456789000', 
    'fingerprint': '8530917420826237752244145897794609217342310051552114638', 
     'from': '02:00:00:00:00:00' , 
     'location': 'Lat:0.0;Log:0.0'
     'to' : 'adhaarDB'}

    """

    
    ############## ADDING DETAILS INTO BLOCCHAIN #############################

    """
    usE OF BLOCKCHAIN WHY : ?
        ANY TRANSACTION LEGAL OR ILLEGAL WILL BE ADDED TO BLOCKCHAIN 
        ILLEGALLY USED , BASED ON LOCATION CULPRIT CAN BE HELD 
        SIMILARLY CLIENT CANNOT DENY HE HAS MADE TRANSACTION AND FOOL THE VENDOR

        EASY TO TRACK THE CUPLPRIT BASED ON LOCATION 
    """

    ### STEP 1 : CREATE TRANSACTION
    print("Creating transaction.......")
    requests.post(node_address + "create_transaction", json = data_encrypted_json)
   

    ### STEP 2 : MINE 
    print("Mining........")
    requests.get(node_address + "mine")
    print("Block added into blockchain........")

    ### STEP 3 : GET CHAIN IF FOR VERIFICATION NOT REQUEIRED
    #r2 = requests.get(node_address + "chain")
    
    
    ############ DATABASE CONNECTION ###############

    print("Attempt to connect MySQL......")
    db = sql.connect(host="localhost", user="root", passwd="mysql", db="details")
    cursor = db.cursor()

    print('Validating Vendor........')

    if cursor.execute("SELECT * FROM VendorDetails where Device_ID like '"+mac+"';"):

        details_vendor = cursor.fetchall() #fetching all details and put them in tuple
        ## VERIFYING WHETHER VENDOR REGISTERED HIS MAC ADDRESS PROPERLY UNDER GOVERNMENT PERMIISSIONS

        if details_vendor[0][2] == "YES":

            print("Authentic Vendor....")
            
            k = cursor.execute("SELECT * FROM AadharDetails where Aadhar_ID like '"+data["uuid"]+"';")
            print(k)
            if not k:
                return jsonify({"transaction" : "invalid uuid"}), 201

            print("Sending OTP........")
            user_details= cursor.fetchall()

            mobile_number = user_details[0][3]
            fingerprint = user_details[0][4]
            all_fingerprints.append( {data["uuid"] : fingerprint } )
            
            opt_generated = random.randint(100000,999999)
            print(opt_generated)
            cursor.execute("SET SQL_SAFE_UPDATES = 0;")
            
            #STORE OPT -USED TO VALIDATE WHEN USER SUBMITS THROUGH APPLICATON
            cursor.execute("update details.AadharDetails set OTP = '"+ str(opt_generated)+"' where Aadhar_ID like '"+data["uuid"]+"';")
            
            # TEEMPARARLY HOLD MAC TO PUT IN TRNASACTION WHEN OTP SUBMITTED FROM USER TO VENDOR 
            cursor.execute("update details.AadharDetails set MAC = '"+ mac_reference +"' where Aadhar_ID like '"+data["uuid"]+"';")
            cursor.execute("update details.AadharDetails set location = '"+ str(data['location']) +"' where Aadhar_ID like '"+data["uuid"]+"';")
            cursor.execute("update details.AadharDetails set timestamp = '"+ str(time.time()) +"' where Aadhar_ID like '"+data["uuid"]+"';")
            db.commit()
            print(mobile_number)
                 ## SMS GATEWAY CODE using nexmo
            client = nexmo.Client(key='6041a8c1', secret='NtKAr9UnxDNsyDUY')
            s = client.send_message({
                'from': 'Nexmo',
                'to': mobile_number ,
                'text': str(opt_generated),
            })
            print(s)


        else:
            return jsonify({"transaction" : "Not registered under govt. Remote governemt agency"}), 201
               
    else:
        return jsonify({"transaction" : "Not a governemt authentic device. Remote to govt. agency immediately"}), 201


    return jsonify({"transaction" : "sucess"}), 201


def key_splitting_cipher(data):

    data = str(data) #aes we are usiing and hence typecast back to string
    l = len(data) #length of the string 
    k1 = data[:int(l/3)] # lenght of the first thrid of the string
    k2 = data[int(l/3) : int( (2*l)/3 )] #lenght of the second third of the string
    k3 = data[int( (2*l)/3 ): ] #lenght of the thrid half of the string

    ####### encrypted data sent to blockchain nodes #################3
   
    data_encrypted1 = EncodeAES(cipher, k1).decode('utf-8') # First one thrid of string  encrypted 
    data_encrypted2 = EncodeAES(cipher, k2).decode('utf-8') # Second one thrid of string  encrypted
    data_encrypted3 = EncodeAES(cipher, k3).decode('utf-8') # Third one thrid of string  encrypted
    
    ####Converrting to json objects ................

    data_encrypted_json1 = { "encrypted_block" : data_encrypted1 }
    data_encrypted_json2 = { "encrypted_block" : data_encrypted2 }
    data_encrypted_json3 = { "encrypted_block" : data_encrypted3 }

    return data_encrypted_json1, data_encrypted_json2, data_encrypted_json3




# when we send otp through our APP , hit this URL
@app.route("/otp" , methods = ["POST"])
def opt_verification():


    #### Request handling 
    print("Verifying OTP...............")
    data = request.get_data()
    data = data.decode("utf-8").split("=")[1]
    data = json.loads(data) # is dictinary here 
    print("888888888888888")
    print(data)
    #connect mysql server
    db = sql.connect(host="localhost", user="root", passwd="mysql", db="details")
    cursor = db.cursor()
    cursor.execute("select otp, mac from details.AadharDetails where Aadhar_ID like '"+data['uuid']+"';")
    q = cursor.fetchall()
    
   
    ######### verifying OTP  ##############

    ############### OUR IDEA and UNQIUE ONE ##############
    ### successfull OTP verification , generate keys using RSA
    ### fetch data from database encrypt with one key and destroy

    ### we are storing public key on block chain
    ### Reason : difficult to recover private key from public key , but viceversa can be done

    ### Distributing the RSA key accross the nodes of Blockchain

    ### we assume we split our key and stores parts of it encrypted with block chain AES256 key and stroed

    if q[0][0] == data['otp']:

        print(data['block_id'])
        block_check = (list(data['block_id']))
        sum_chk = int(block_check[1]) + int(block_check[3]) + int(block_check[5])

        if not sum_chk:
            #print(block_check)
            #print(sum(data['block_id'])))
            print("Successfull OTP verification and very first transaction...........")

            ###############     GENERATING RSA KEYS        ############################
           
            
            uuid = data['uuid']
            db = sql.connect(host="localhost", user="root", passwd="mysql", db="details")
            cursor = db.cursor()
            ## VERIFYING ADHAAR CREDENTIALS
            cursor.execute("SELECT * FROM AadharDetails where Aadhar_ID like '"+ uuid +"';")
            user_details= cursor.fetchall()
            ### OTP goes to registered MOBILE APPLICATION FOR 2 FACTOR AUTHENTICATION
            ## VALIDATING FINGERPRINT
            _fingerprint_ = user_details[0][4]  

            ## COMPARING WITH USER GIVEN FINGERPRINT 
            print('validating fingerprint......')  
            print(uuid)
            data_given = [ i[uuid] for i in all_fingerprints if uuid in i.keys() ][0]
            if _fingerprint_ == data_given:
                print("Successfully authenticated the user ..........")
                print("Generating keys....")
                p,P = rsa() # p =public key , P =private key

        
                """

                fetch that uuid account user details and update with current private key

                use encrypt method

                cursor.execute("SELECT * FROM AadharDetails where Aadhar_ID like '"+uuid+"';")
                user_details= cursor.fetchall()
                
                name = user_details[0][2]
                mobile = user_details[0][3]
                fingerprint = user_details[0][4]
                email = user_details[0][5]
                e_name = encrypt(P, name)
                e_mobile = encrypt(P, mobile)
                e_fingerprint = encrypt(P, fingerprint)
                e_email = encrypt(P, email)
                cursor.execute("SET SQL_SAFE_UPDATES = 0;")

                # check this one out
                cursor.execute("UPDATE details.AadharDetails SET Name=%s, Mobile=%s, FingerPrint=%s, EmailID=%s WHERE Aadhar_ID=%s", (e_name, e_mobile, e_fingerprint, e_email, data["uuid"]))
                db.commit()


                """



                print ("Your public key is " + str(p)+ " and your private key is "+ str(P))


                ##### UPDATING THE RECORDS AND ENCRYPTING WITH PRIVATE KEY AND STROING THEM IN DB ###################


                data["to"] = q[0][1] # adding new key values in dictionary
                data["key"] = str(p)
                data['timestamp'] = str(time.time())
                #data["key"] = "esGjXL1MNHjWw5uFxdl3CVv9fHynxBgNhADpXw9v7aM4adM9PhKpprEgjYOctBQwWbPwIJwJ8MWXL10aVsHhT/zCE1ShkUiCjCXlGxtstvoegW0KtPgIQ43k2Q/aDxlhNrQvqWuSvOVhE3zqgPorUg==#" #"New RSA public key" #updating key with newly generated rsa key
                original_key = data['key']
                #thi long is RSA key
                #lets split rsa to 3 strings
                
                e1, e2, e3 =key_splitting_cipher(data)#our data is dictinary
                #entire dictionary is split by converting the dictinary to string and then splitting the string to 3 halves

                ##### ASSUNING ATLEAST 3 NODES , SO THAT KEY WOULD BE SENT TO THOSE THREE NODES ####################
                data_encrypted = [ e1, e2, e3]

                verify_decode = [] #stroing parts of decrepted key 
                block_location = []


                ######################################################################
                ######### STORING PUBLIC KEY ON BLOCKCHAIN  ##########################
                ######################################################################

                print("Adding the new Key to blockchain...........")

                for node,data in zip(node_address_otp,data_encrypted):
                    requests.post(node + "create_transaction", json = data)
                    #returns the block id
                    blockID = requests.get(node + "mine").content
                    print(blockID)
                    print(type(blockID))
                    # we getting block ID from json response           
                    block_location.append(json.loads(blockID.decode('utf-8').replace("'",'"'))['id'])
                    chain=requests.get(node + "chain").content
                    chain = chain.decode('utf-8')
                    #I am taking the last block 
                    chain = (json.loads(chain))['chain'][-1]['transaction'][0]['encrypted_block']
                    #acessing the encrypted block 
                    ##### decrypting the part of the key
                    decoded = DecodeAES(cipher, chain).decode('utf-8')
                    ##### appedning the original recovered partial key
                    verify_decode.append(decoded)

                print("Phase Two Done")
                block_location_to_user = { "id" : str(block_location)}
                print(block_location_to_user)

                v = (verify_decode[0] + verify_decode[1] + verify_decode[2]).replace("'", '"')
                print(v)
                print("########")
                _key_ = json.loads(v)["key"]
                uuid = json.loads(v)["uuid"]
                #extracting the key....Used for decrypting the database records of one individaul
                print(_key_)#verifying whether key matched or not
                return jsonify({"transaction" : "Successfull.User Authenticated"}), 201
               
            else:
                return jsonify({"transaction" : "Try again. FingerPrint did'nt match"}), 201
        else:
            print("RSA Encryption now ")
    else:
        print("Wrong OTP..............")
        return({"message": "Wrong OTP" })

    return jsonify({"message": "Wrong OTP"}),201


app.run(debug=True,host="10.1.95.243", port=9000)
