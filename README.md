# Securing-Aadhaar-Details
TITLE: ENCRYPTION OF BIOMETRIC TRAITS TO AVOID PRIVACY ATTACK.

PROBLEM STATEMENT: Now a day the declaration of biometric and other personal data has been imposed not only by the Govt., but by many private entities also. There is no proper mechanism and assurance that these data will be kept safe by such agencies. This is a giant problem and the Hon’ble Supreme Court of India has also intervened into this matter. Hence, technological solution must be devised to prevent the loss, misuse of such data on Internet.

OUR SOLUTION: We propose govt to provide all the the vendors with fingerprint scanners with a unique Id,(ie mac number of the machine.)and store them in a data base we used MySQL to simulate it,initially we use AES 256 encryption to encrypt the database.All the users must register their adhaar details to the govt and get the client application installed in their mobiles. Our basic idea is a two way authentiaction that is whenever any vendor makes a query for adhaar details then the client will get an otp or an email,If the vendors transaction is genuine then he will grant him access by typing the OTP in an mobile application or via email.

Our main idea is deploying the blockchain over database where all the transaction details are added into block chain network which helps to track the bad transactions or illegal transactions based on transaction data. For every successful transaction server generate two keys using RSA 2048 encryption, the private and public keys(for each transaction we are reinforcing the clients data by encrypting it with new RSA private key).

We use this private key to encrypt the clients data in the database and then we destroy the private key and store the public key in transaction's data and deploy on block chain itself. Even if govt servers got compromised by an adversary, he cant decrypt as he requires public key to decrypt it which has been incorporated on the block chains.To further increase the complexity we distributed the public key among three 3 to 4 blocks. The correspoding block id numbers are sent to client to track them easily when successful two factor authentication is done. If attacker could find public key by trail and error method, although he decrypts it, in order for the data to be meaningfull on database for user to access those details ,only garbage data is returened when server decrpyts because he didnt encrypt with the original legitiamte private key used by server. Generating privtae key from public key is very difficuklt and hence we stored public key on blockchain. To account for the efficiency we used decentralised server distribution ,like north india has one server and south india has another we then allocate all nothern states with a server under north domain.Similarly all southern states are allocated servers under southern domain the bolck chains will be deployed over all the servers distinctly.Also if any northern states server got damaged or corrupted then it can easily retrive the data from crntral northern server. If some adversary tries to tamper block chain he get caught,as we are storing the gps locations of every transaction by following block chain we can easily deduce the unique Id of the person.(Block chains cant be tampered as they are widely distributed and one must tamper all the nodes at the same momment which is impossible.)

TESTING DESCRIPTION: Two blockchains One for VENDOR running on PORT 4000 localhost - One Node Architecture One for OTP TRANSACTION running on PORT 5000,5001,5002 respectively on localhost - THREE Node Architecture

SERVER RUNNING ON PYTHON 9000 and ip address of the computer

commands as follows on terminal python opt_transaction_blockchain.py -p 5000 python opt_transaction_blockchain.py -p 5001 python opt_transaction_blockchain.py -p 5002

python vendor_transaction_blockchain.py -p 4000

python biometrics_server.py Requirements: Flask,MySQLDB
