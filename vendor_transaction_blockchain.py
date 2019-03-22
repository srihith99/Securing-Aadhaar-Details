
#####################         SIH 2019        ###################
#####################    CIRCUIT BREAKERS     ####################
#####################    IITH HYDERABAD       ####################


#####################PYTHON CODE RUNNING ON NODE THAT IMPLEMENTS BLOCKCHAIN ###################
import json, requests, random, string
import hashlib as h
from flask import Flask,jsonify, request
from uuid import uuid4

################ BLOCK CHAIN #######################
################ Running on local host port 4000 ##################


#### Needed Library ----------- Flask


import optparse
parser = optparse.OptionParser()

parser.add_option("-p","--port",dest="port",help ="target port",default = 5000,type=int)
parser.add_option("-i","--host",dest="host",default="127.0.0.1", help = "ip")
(options,args) = parser.parse_args()

if not options.port:
    print("Error")

################ BLOCK CHAIN #######################
################ Running on local host port 4000 ##################


#### Needed Library ----------- Flask


_port_ = options.port
_ip_  = options.host
print(_ip_)
print(_port_)

class BlockChain():

    def __init__(self):
        
        self.chain= []
        #this list holds all blocks ... BLOCKS are dict type and inside DICT , there is another dict for transaction
        self.hold_all_block_transactions = []
        self.nodes_decentralized = set() #set is used not list because to prevent from repeatations
        self.create_genesis()
        #genesis is the first block . We set its block ID as 1, pow =0  and prev_hash =0 and transcation as null
        #note that for genesis block , transcation is empty list []
        #for rest of all blocks transaction is dict type {} ####### not [] ###########

    def block(self, index, proof, prev_hash, transaction):
        ### proof is nonce here and it keeps on changing 
    
        #our block is dict type completely
        # and we are appendign to the list chain that has all our blocks which are dict type

        """
                ##### BLOCK Structure #####

                {
                        "index" : 24,   #this is block ID
                        
                        "pow" : 91,     #pow alogrithm , this returns simple int generated by using 
                                        #prev pow and then apply our algo to generate new pow for new block
                        
                        "prev_hash": "abcdef...." 
                                        #hash value of rpevious block

                        "transaction" : [ 
                                           { 
                                            ############### First transaction  ###################
                                            ### our transcation is DICT type ###
                                            ######   EXAMPLE  ######
                                
                                            "from" : "vendor mac" ,
                                            "to"   : "adhaardb",
                                            "uuid" : "2567823451111",
                                            "location" : "hyderabad"
                                            "fingerprint" : "<Encrypted fingerprint send from vendor>"
                                           }
                                        ] 
                        "timestamp" : 2256782.6712 #we use time.time()
                }

        """


        # NOTE : Transcation is list  type with dict elements  and the list is inside the block which is dict type 
        new_block = { "index":index, "proof":proof,"hash":prev_hash,"transaction": transaction }
        return new_block

        
        
    
    def proof_of_work_algorithm(self):
        nonse= ''.join(random.choice(string.ascii_uppercase+ string.ascii_lowercase + string.digits) for _ in range(16))
        #16 character nonse random alphanumeric string 
        return nonse


    def prev_proof_currentstate_block(self):
        
        return (self.chain[-1]["proof"])
        
        
    def hash_currentstate_block(self):
        ### This will hash the 

        #BLOCk ID  + POW + previous block hash value  + Data or transaction + timestamp

        return h.sha256(json.dumps(self.chain[-1],sort_keys=True).encode('utf-8') ).hexdigest()
    
    def hash_mine_block(self,block):
        #### This function will give the hash of newly supposed to be added block in the block chain
        #### We say this newly block as Mining block and after successfully found out signature we
        ###  We have mined our block and then add our mined block into our block chain

        return h.sha256(json.dumps(block,sort_keys=True).encode('utf-8') ).hexdigest()


    def find_proof_ofWork(self, prev_proof):
        #simple algorithm
        proof = prev_proof + 1
        
        
        while (proof + prev_proof )%7 !=0:
            proof+=1
        
        return proof

    def mining_algorithm(self, hash):
        # Hashing our new block
        # Higly computationl
        ##########  Signature is hash value begining with 0011 ###################
        ##conmputations for second mined block went around 135708
        #### if signature beomes complecated it takes very high time

        ## Genesis block is called first and it must also satisfy the signature


        try:
            a1 = int(hash[0])
            a2 = int(hash[1])
            a3 = int(hash[2])
            a4 = int(hash[3])
            #a5 = int(hash[4])
            #a6 = int(hash[5])
            if a1 == a2 and a1 == 0 and a3 == a4 and a3 == 1 :#and a5 == a6  and a5 == 2:
                return True
            else:
                return False
        except Exception:
            return False


 
    def create_new_transaction_list_input(self,details):
        # detials i recieved will be in the form of list here 
        ###### update mac with from
        
        ################  TRANSACTION IN UNENCRYPTED FORMAT #################
        #### BUT WE ARE NECRYPTING OUR TRANSACTION USING AES 256   #####################
        ################NEW BLOCK TRANSACTION LOOKS LIKE #######################

        transaction =  {    "encrypted_block": "ABCDEFGHIJKLMNOPQRSTUVWXYZ" }
        #transaction =  {    "mac": "vendorMAC","to": "adhaarDB","location": "200","uuid" : "adhaarID" , "fingerprint":"sendbyvendor" } #default set values
        ### Our transaction dict structure ........Modify here to add data contents etc....

        keys = transaction.keys()
        #getting dictinary key values in transaction
        for val,k in zip(details, keys):
            transaction[k] = val

        #self.hold_all_block_transactions.append(transaction)
        return transaction
        #transcation is a dict type 
        #FORMAT:
        # {   "aaa" : "aaa"  , "bbb":"bbb" , .....   }
            

    def create_new_transaction(self,details):
        #### This fucntion used when i recieve data from web server as Json objects direclty
        #### Details are of dict type
        # detials i recieved will be in the form of list here 
       
        self.hold_all_block_transactions.append(details)
        
        #transcation is a dict type 
        #FORMAT:
        # {   "aaa" : "aaa"  , "bbb":"bbb" , .....   }
        return self.hold_all_block_transactions

    def register_nodes_decentralized(self, node_ip):
        # Now we are decentralizing the block chain
        # => implies we have many nodes not the single node
        # each node acts liek a server
        # parent server keeps track of all the nodes in the network

        self.nodes_decentralized.add(node_ip)

    def all_nodes_chains(self, relative_url):
        neighbouring_nodes_chains = []

        for address_node in list(self.nodes_decentralized):
            url = address_node + relative_url
            try:
                data = requests.get(url).json()
                neighbouring_nodes_chains.append(data['chain'])
            except requests.exceptions.ConnectionError:
                pass

        return neighbouring_nodes_chains

    

    def mining(self, mine_address):
        #self.consensus_algorithm()
        
	#miner address is the node address in the memory. Use uuid4 in hex to send the node address

        miner_fees = self.create_new_transaction_list_input([ "0" , mine_address, 1000, 444444 ])
        #this returns the type dict 
        self.hold_all_block_transactions.append(miner_fees)
        #previous hash value
        prev_hash  = self.hash_currentstate_block()
        #getting previous hash of the last block of existing block chain and input to new block supposed 
        #to be added

        all_transaction = self.hold_all_block_transactions
        ### this returns the block which is dict type 
        ### Mining algorithm
        ### Mining algorithm

        c =0
        while True:

            nonse = self.proof_of_work_algorithm()
            block = self.block(len(self.chain) + 1, nonse, prev_hash, all_transaction)
            ### this returns the block which is dict type
            # calling mining algorithm
            if self.mining_algorithm(self.hash_mine_block(block)):
                self.add_block(block, self.hash_mine_block(block))
                break
            c = c +1

        print("@@@@@@@@@@@  "+str(c))
        self.hold_all_block_transactions = []
        #self.add_block(block)
        return block
    

    def add_block(self, block, signature):
        self.chain.append(block)
           



    def create_genesis(self):
        _random_ = self.proof_of_work_algorithm()
        genesis_hash = h.sha256( _random_.encode("utf-8") ).hexdigest()
        genesis_hash = genesis_hash.replace(genesis_hash[0], '0')
        genesis_hash = genesis_hash.replace(genesis_hash[1], '0')
        genesis_hash = genesis_hash.replace(genesis_hash[2], '1')
        genesis_hash = genesis_hash.replace(genesis_hash[3], '1')
        ### First 6 pattern matching as signature -- higly computational intensive
        while True:
            nonse = self.proof_of_work_algorithm()
            genesis_block = self.block(len(self.chain) + 1, nonse, genesis_hash, [])  #empty transcation of type list only for genesis block
            ### this returns the block which is dict type
            # calling mining algorithm
            if self.mining_algorithm(self.hash_mine_block(genesis_block)):
                self.add_block(genesis_block, 0)
                break


app = Flask(__name__)
blockchain = BlockChain()
node_address = uuid4().hex #unique address for current node



@app.route('/create_transaction', methods= ['POST'])
def create_transaction():

    transaction_data = request.get_json()#requewst from user in json format
    #details_to_make_new_transaction = [ transaction_data[key] for key in transaction_data.keys() ]
    fn1 = blockchain.create_new_transaction(transaction_data)
    response = { "message" : "transaction successfully submitted" , "block_index":fn1}
    return jsonify(response), 201


@app.route("/mine",methods=["GET"])
def mine():
    mined_block_details = blockchain.mining(node_address)
    response = { "message" : "transaction successfully submitted" , "block_data":mined_block_details}
    return jsonify(response)

    

@app.route("/chain",methods=["GET"])
def chain():
    get_full_chain = blockchain.chain
    #print(get_full_chain)
    response = {"chain" : get_full_chain }
    return jsonify(response)


@app.route("/register_node", methods = ["POST"])
def register_node():
    new_node = request.get_json()
    print(new_node)
    blockchain.register_nodes_decentralized(new_node["address"])
    response = {  "message" : "Node added" , 

                  "node_details": [ 
                                        {  "node_count" : len(list(blockchain.nodes_decentralized)) ,
                                            "address" : list(blockchain.nodes_decentralized) 
                                        }
                                  ] 
                }

    return jsonify(response),201


@app.route("/consensus_protocol", methods = ["GET"])
def consensus():

    neighbouring_nodes_chains = blockchain.all_nodes_chains("chain")
    #this is list of all the neighbouring nodes ....
    #which is a list of dict objects where it has transactional data that is list of dict objects

    #print(neighbouring_nodes_chains)

    if not neighbouring_nodes_chains:
        return jsonify( {
                            "message" : "Single node architecture"
                        }
                      ) 
    longest_chain = max(neighbouring_nodes_chains, key = len) # this format we get is list
    #this list has the blocks in dict format
    max_chain_size_in_network = len(longest_chain)
    current_blockchain_size = len(blockchain.chain)

    if current_blockchain_size >= max_chain_size_in_network:
        return jsonify( { 
                           "message" : "Current blockchain has maximum chain",
                           "current_size" : current_blockchain_size,
                           "next_highest_size_chain": max_chain_size_in_network
                        }
                      )
    else:
        blockchain.chain = longest_chain
        return jsonify( {
                            "message"   : "Current blockchain updated with longest chain",
                            "new_chain" : blockchain.chain
                        } 
                      ) 


app.run(debug=True,host=_ip_, port=_port_)
