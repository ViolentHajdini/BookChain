import hashlib
import os
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
from flask import Flask, jsonify, request
import urllib.request
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization


class Blockchain:
    def __init__(self, title, host):
        #where transactions will be stored
        self.current_transactions = []
        #array for chain
        self.chain = []
        #list of nodes as a set, none repeating
        self.nodes = set()
        #Appends the information for a book to the genesis block for the book created
        self.book = title
        self.current_transactions.append({ "sender" : host , "recipient" : host})
        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)
        # Create the this node's private key
        self.private_key = ec.generate_private_key(ec.SECP384R1())

    """

    """

    @staticmethod
    def chain_hash(chain):
        chain_hash = hashes.Hash(hashes.SHA256())
        for block in chain:
            chain_hash.update(str(block['index']).encode())
            chain_hash.update(str(block['previous_hash']).encode())
            chain_hash.update(str(block['proof']).encode())

        return chain_hash.finalize().hex()

    def register_node(self, address):
        """
        Add a new node to the list of nodes
        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def valid_chain(self, chain):
        """
        Helper function to determine the chains validation
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")

            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False
            # Proof of Work
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self, book):
        """
        Consensus algorithm
        """
        token = str(book.replace(' ','_'))
        neighbours = self.nodes
        new_chain = None
        # We're only looking for chains longer than ours
        max_length = len(self.chain)
        print(token)
        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            
            print('this is a nodesdasdadasd :',node)
            response = requests.get(f'http://localhost:{node}/{token}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                signature = bytes.fromhex(response.json()['signature'])
                public_key = serialization.load_der_public_key(bytes.fromhex(response.json()['public_key']))

                try:
                    hash_check = bytes.fromhex(self.chain_hash(chain))
                    public_key.verify(signature, hash_check, ec.ECDSA(hashes.SHA256()))
                except:
                    return False

                # Check if the length is longer and the chain is valid
                # if valid it replaces and checks for length
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain
        if new_chain:
            self.chain = new_chain
            return True
        return False

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain
        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        """

        block = {
            'index': len(self.chain) + 1,
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient):
        """
        Creates a new transaction between sender and recepient that
        gets added as a block in the blockchain
        """
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient
        })

        return self.last_block['index'] + 1

    #get the last block in the blockchain
    @property
    def last_block(self):
        return self.chain[-1]


    #hashes the block
    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: Block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:
         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof
         
        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof of Work
        """
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


    def retrieve_signature(self):   
        """
        Turn blockchain hash into a bytes string to sign
        """
        hash = bytes.fromhex(self.chain_hash(self.chain))

        signature = self.private_key.sign(
            hash,
            ec.ECDSA(hashes.SHA256())
        )

        return signature.hex()


    #requests.post(url, data={key: value}, json={key: value}, args) 
    #example of a post request
    #url = 'https://www.w3schools.com/python/demopage.php'
    #myobj = {'somekey': 'somevalue'}

    #x = requests.post(url, data = myobj)

    #helper function to spread keys
    def spread_key(self, key):
        neighbours = self.nodes
        for node in neighbours:
            x = requests.post(f'http://{node}/recieve/id', json = {'key':key})
    
    #helper function to broadcast IDs
    def broadcastID(self,key):
        neighbours = self.nodes

        for node in neighbours:
            token = requests.get(f'http://{node}/request/list')
            arr = token.json()['list']
            if key in arr:
                return True
        return False


# Instantiate the Node
app = Flask(__name__)

class Manager: 
    """
    Manager class to oversee the blockchains, it is needed since when a node instatiates a blockchain
    or starts a bood, we need to share that immediately with other nodes since he would be the first owner
    """
    def __init__(self):
        self.library = []
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.nodes = set()
    """
    Finds the last recepient by looking in the blockchains last block for recepient
    """
    def last_recipient(self, index):
        return self.library[index].last_block['transactions'][0]['recipient']
    
    """
    Searches the Manager array for a specific book title recieved from the route
    """
    def search(self, book):
        for x in range(0, len(self.library)):
            if (self.library[x].book == book):
                return x
        return -1

    """
    Finds the last recepient by looking in the blockchains last block for recepient
    """
    def register_node(self, address):
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')
    

    """
    A form of broadcast between the nodes to get the most recent books
    """
    def share_book(self, index):
        data = {
            'book': self.library[index].book,
            'owner_url': request.host,
            'chain': self.library[index].chain
        }
        for node in self.nodes:
            response = requests.post(f'http://localhost:{node}/share/book', json={'Data': data})
   
    """
    Hashing helper functions
    """
    def hash_key(self, key):
        token = hashes.Hash(hashes.SHA256())
        token.update(str(key).encode())
        return token.finalize().hex()

    """
    The request is sent, and verification for person who claims to have the book  
    """
    def hashed_information(self, index, key):
        signature = self.private_key.sign(
            bytes.fromhex(self.hash_key(key)),
            ec.ECDSA(hashes.SHA256())
        )
        public_key = self.private_key.public_key()
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        data = {
            'pubkey' : serialized_public_key.hex(),         
            'sig' : signature.hex(),
            'index' : index
        }
        verifies = 0
        for node in self.nodes:
            print('nodes are :', node)
            response = requests.post(f'http://localhost:{node}/verify', json = {'Data' : data})
            if(response.status_code == 201):
                verifies += 1

        print(verifies)
        if(verifies == (len(self.nodes))):
            
            return True
        return False

    """
    Helper function to verify owner 
    """
    def verify_owner(self, index, host):
        url = self.last_recipient(index)
        data = {
            'index' : index,
            'host': host
        }
        print(f'node: {request.host} function :verify_owner()')
        response = requests.post(f'http://{url}/owner', json={'Data':data})
        if (response.status_code == 201):
            return True
        return False
            
    """
    Helper function for public key verification
    """
    def retrieve_signature(self, key, sig,pubkey):
        public_key = serialization.load_der_public_key(bytes.fromhex(pubkey))   
        try:
            public_key.verify(bytes.fromhex(sig), key, ec.ECDSA(hashes.SHA256())) 
        except:
            return False
        return True
    
    """
    Broadcast for manager class, resolves any inconsistencies within blockchain books
    """

    def manager_resolve(self, index):
        for node in self.nodes:
            response = requests.post(f'http://localhost:{node}/node/resolve', json = {'index': index })
        return
        
     
# Instantiate the library
Manager = Manager()

#helper route to verify owner
@app.route('/verify', methods=["POST"])
def verify_sender():
    values = request.get_json()
    token = Manager.last_recipient(values['Data']['index'])
    verify = bytes.fromhex(Manager.hash_key(token))
    hash_check = Manager.retrieve_signature(verify, values['Data']['sig'], values['Data']['pubkey'])
    if (hash_check):
        return 'verified', 201
    return 'not verified', 400
    
#helper route finding the owner for the requester of a book
@app.route('/owner', methods=['POST'])
def verifyOwner():
    values = request.get_json()
    print(f'node {request.host} at route owner ',request.host)
    if(Manager.hashed_information(values['Data']['index'], request.host)):
        Manager.library[values['Data']['index']].new_transaction(request.host, values['Data']['host'])
        proof = Manager.library[values['Data']['index']].proof_of_work(Manager.library[values['Data']['index']].last_block)
        previous_hash = Manager.library[values['Data']['index']].hash(Manager.library[values['Data']['index']].last_block)
        Manager.library[values['Data']['index']].new_block(proof, previous_hash)
        Manager.manager_resolve(values['Data']['index'])
        print(f'at {request.host} at owner print new last block:' , Manager.library[values['Data']['index']].last_block )
        return 'owner found', 201
    return 'owner dead', 400
    
#broadcast route for all the nodes to update the book thats newly added
@app.route('/share/book', methods=['POST'])
def share_books():
    values = request.get_json()
    new_book = Blockchain(values['Data']['book'],values['Data']['owner_url'])
    new_book.chain = values['Data']['chain']
    new_book.nodes = Manager.nodes
    Manager.library.append(new_book)

    return 'synch', 201

#Adds a new book depending on the route
@app.route('/library/new', methods=['POST'])
def new_book():
    values = request.get_json()
    host = request.host
    book = Blockchain(values["book"], host)
    Manager.library.append(book)
    Manager.share_book(len(Manager.library)-1)

    return jsonify("New Book Added to the Library"), 201

#Displays book
@app.route('/book', methods=['GET'])
def list_book():

    response = [] 
    for x in Manager.library:
        response.append({"Book Title" : x.book})   
    return jsonify(response), 201

#creates a new transaction thats added to the block
@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'book']
    if not all(k in values for k in required):
        return 'Missing values', 400

    blockchain = Manager.library[Manager.search(values['book'])]

    # Create a new Transaction
    index = blockchain.new_transaction(
        values['sender'], values['recipient'])

    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)
    
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }

    return jsonify(response), 200

# @app.route('/user/<username>')
# Gets the blockchain of a specific book
@app.route('/<book>/chain', methods=['GET'])
def full_chain(book):
    x = str(book.replace('_', ' '))
    token = Manager.search(x)
    print(token)
    blockchain = Manager.library[token]

    public_key = blockchain.private_key.public_key()
    serialized_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    host = request.host

    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
        'signature': blockchain.retrieve_signature(),
        'public_key': serialized_public_key.hex(),
        'hash': blockchain.chain_hash(blockchain.chain)
    }
    return jsonify(response), 200

#registers other nodes 
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        Manager.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(Manager.nodes)
    }
    return jsonify(response), 201

#sends a request for a specific book
@app.route('/<book>/request', methods=['GET'])
def request_book(book):
    token = str(book.replace('_',' '))
    x = Manager.search(token)
    url = request.host
    print('owner url', url)
    if(Manager.verify_owner(x, url)):
        response ={
            'message': 'it worked'
        }
        return jsonify(response),200
    else:
        response = {
            'message': 'it did not work'
        }
        return jsonify(response),400

#calls the resolve conflict, mass consensus 
@app.route('/node/resolve', methods=['POST'])
def consensus():
    values = request.get_json()
    replaced = Manager.library[values['index']].resolve_conflicts(Manager.library[values['index']].book)

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': Manager.library[values['index']].chain
        }
        return 'yes consensus', 201
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': Manager.library[values['index']].chain
        }
        return 'no consensus', 201

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000,
                        type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port, debug=True)
