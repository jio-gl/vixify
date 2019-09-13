'''
title           : blockchain.py
description     : A blockchain implemenation
author          : Adil Moujahid
date_created    : 20180212
date_modified   : 20180309
version         : 0.5
usage           : python blockchain.py
                  python blockchain.py -p 5000
                  python blockchain.py --port 5000
python_version  : 3.6.1
Comments        : The blockchain implementation is mostly based on [1]. 
                  I made a few modifications to the original code in order to add RSA encryption to the transactions 
                  based on [2], changed the proof of work algorithm, and added some Flask routes to interact with the 
                  blockchain from the dashboards
References      : [1] https://github.com/dvf/blockchain/blob/master/blockchain.py
                  [2] https://github.com/julienr/ipynb_playground/blob/master/bitcoin/dumbcoin/dumbcoin.ipynb
'''

from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

import requests
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS

from vdf import vdf_execute, vdf_verify, vdf_prime
import vrf as vrf
RsaPublicKey = vrf.RsaPublicKey
RsaPrivateKey = vrf.RsaPrivateKey
VRF_Prove = vrf.VRF_prove

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
# Each difficulty is 4 zero bits on the hash target, so 5*4=20 is good, but 6*4=24 is too many seconds for testing.
MINING_DIFFICULTY = 5
TIME_MINING_DIFFICULTY = 10000
USE_PROOF_OF_TIME = True
DEFAULT_DEBUG_STAKE = 25000
TOTAL_COINS = 100000


class Blockchain:

    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()
        #Generate random number to be used as node_id
        self.node_id = str(uuid4()).replace('-', '')
        #Create genesis block
        self.create_block(0, '00')
        print('Initializing blockchain...')
        self.create_rsa_keys()

    def create_rsa_keys(self):
        print('Creating RSA keys...')
        self.keys = RSA.generate(2048, None, None)


    def get_vrf_private_key(self):
        pem_private_key = self.keys.exportKey('PEM')
        hazmat_private_key = serialization.load_pem_private_key(pem_private_key, password=None, backend=default_backend())
        #hazmat_private_key = serialization.load_pem_private_key(
        #    key_file.read(),
        #    password=None,
        #    backend=default_backend()
        #)

        hazmat_public_key = hazmat_private_key.public_key()

        private_numbers = hazmat_private_key.private_numbers()
        public_numbers = hazmat_public_key.public_numbers()
        n = public_numbers.n
        e = public_numbers.e
        d = private_numbers.d
        k = 20

        #public_key = RsaPublicKey(n, e)
        # private_key = RsaPrivateKey(n, d)
        return RsaPrivateKey(n, d)

    def VRF_Hash(self, pk, last_hash):
        k_fruta=20
        return vrf.VRF_prove(pk, last_hash, k_fruta)


    def register_node(self, node_url):
        """
        Add a new node to the list of nodes
        """
        #Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')


    def verify_transaction_signature(self, sender_address, signature, transaction):
        """
        Check that the provided signature corresponds to transaction
        signed by the public key (sender_address)
        """
        public_key = RSA.importKey(binascii.unhexlify(sender_address))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(signature))


    def submit_transaction(self, sender_address, recipient_address, value, signature):
        """
        Add a transaction to transactions array if the signature verified
        """
        transaction = OrderedDict({'sender_address': sender_address, 
                                    'recipient_address': recipient_address,
                                    'value': value})

        #Reward for mining a block
        if sender_address == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        #Manages transactions from wallet to another wallet
        else:
            transaction_verification = self.verify_transaction_signature(sender_address, signature, transaction)
            if transaction_verification:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                return False


    def create_block(self, nonce, previous_hash):
        """
        Add a block of transactions to the blockchain
        """
        block = {'block_number': len(self.chain) + 1,
                'timestamp': time(),
                'transactions': self.transactions,
                'nonce': nonce,
                'previous_hash': previous_hash,
                'miner_id': self.node_id,
                }

        # Reset the current list of transactions
        self.transactions = []

        self.chain.append(block)
        return block


    def hash(self, block):
        """
        Create a SHA-256 hash of a block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()


    def proof_of_work(self):
        """
        Proof of work algorithm
        """
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)

        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1

        return nonce

    def vdf_input(self,last_hash,node_id=None, add_vrf=True):
        if node_id == None:
            node_id = self.node_id
        
        print("DEBUG: TXs = %s" % str(self.transactions))
        print("DEBUG: last_hash = %s" % str(last_hash))
        print("DEBUG: node_id = %s" % str(node_id))

        vdf_input = (str(self.transactions)+str(last_hash)+str(node_id)).encode()
        vdf_input_hash = hashlib.sha256(vdf_input).hexdigest()
        vdf_input_integer = int(vdf_input_hash, 16) % vdf_prime
        print("DEBUG: vdf_input_integer = %d" % vdf_input_integer)
        return vdf_input_integer#, 0 #node_vrf_seed

    def proof_of_time(self): # proof_of_random_time()
        """
        Proof of time algorithm
        """
        last_block = self.chain[-1]
        last_hash = self.hash(last_block)

        # VDF input
        vdf_input_integer = self.vdf_input(last_hash)

        # adding VRF (WIP) 
        node_vrf_private_key = self.get_vrf_private_key()
        node_vrf_seed = self.VRF_Hash(node_vrf_private_key, last_hash)
        print('aca vieneeee el seeed')
        print(node_vrf_seed)
        # Calcule VDF Steps needed.
        #node_stake = self.get_node_stake()
        #node_vdf_steps = seed_to_slots(node_stake, node_vrf_seed)

        #node_vrf_private_key = self.get_vrf_private_key()
        #hashed_vdf_input = VRF_prove(node_vrf_private_key, vdf_input_integer, k)

        print("DEBUG: Mining sequential VDF (Sloth) ...")
        #nonce = vdf_execute(vdf_input_integer,node_vdf_steps) # VRF version
        nonce = vdf_execute(vdf_input_integer,TIME_MINING_DIFFICULTY)
        print("DEBUG: Generated NONCE = %d" % nonce)
        return nonce #, node_vrf_seed # with this


    def valid_proof(self, transactions, last_hash, nonce, miner_id, difficulty=MINING_DIFFICULTY):
        """
        Check if a hash value satisfies the mining conditions. This function is used within the proof_of_work function.
        """
        if not USE_PROOF_OF_TIME: # use Proof-of-Work
            guess = (str(transactions)+str(last_hash)+str(nonce)).encode()
            guess_hash = hashlib.sha256(guess).hexdigest()
            return guess_hash[:difficulty] == '0'*difficulty
        else:
            x = self.vdf_input(last_hash,miner_id)
            t = TIME_MINING_DIFFICULTY
            print("DEBUG: Checking NONCE = %d" % nonce)
            y = nonce
            verified = vdf_verify(y, x, t)
            print("DEBUG: Valid Block = %s" % str(verified))
            return verified

    def valid_chain(self, chain):
        """
        check if a bockchain is valid
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            #print(last_block)
            #print(block)
            #print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            #Delete the reward transaction
            transactions = block['transactions'][:-1]
            # Need to make sure that the dictionary is ordered. Otherwise we'll get a different hash
            transaction_elements = ['sender_address', 'recipient_address', 'value']
            transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]

            if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], block['miner_id'], MINING_DIFFICULTY):
                return False

            last_block = block
            current_index += 1
        return True

    def resolve_conflicts(self):
        """
        Resolve conflicts between blockchain's nodes
        by replacing our chain with the longest one in the network.
        """
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            print('http://' + node + '/chain')
            response = requests.get('http://' + node + '/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            return True

        return False

# Instantiate the Node
app = Flask(__name__)
CORS(app)

# Instantiate the Blockchain
blockchain = Blockchain()

@app.route('/')
def index():
    return render_template('./index.html')

@app.route('/configure')
def configure():
    return render_template('./configure.html')



@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.form

    # Check that the required fields are in the POST'ed data
    required = ['sender_address', 'recipient_address', 'amount', 'signature']
    if not all(k in values for k in required):
        return 'Missing values', 400
    # Create a new Transaction
    transaction_result = blockchain.submit_transaction(values['sender_address'], values['recipient_address'], values['amount'], values['signature'])

    if transaction_result == False:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to Block '+ str(transaction_result)}
        return jsonify(response), 201

@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    #Get transactions from transactions pool
    transactions = blockchain.transactions

    response = {'transactions': transactions}
    return jsonify(response), 200

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.chain[-1]
    if USE_PROOF_OF_TIME:
        nonce = blockchain.proof_of_time()
    else:
        nonce = blockchain.proo f_of_work()

    # We must receive a reward for finding the proof.
    blockchain.submit_transaction(sender_address=MINING_SENDER, recipient_address=blockchain.node_id, value=MINING_REWARD, signature="")

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_block(nonce, previous_hash)

    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200



@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.form
    nodes = values.get('nodes').replace(" ", "").split(',')

    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': [node for node in blockchain.nodes],
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


@app.route('/nodes/get', methods=['GET'])
def get_nodes():
    nodes = list(blockchain.nodes)
    response = {'nodes': nodes}
    return jsonify(response), 200



if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)








