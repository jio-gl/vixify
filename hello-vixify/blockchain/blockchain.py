"""
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
"""
import base64
import hashlib
import random
import json
import requests

import stakes
from typing import List, Dict, Union
from collections import OrderedDict

from time import time
from urllib.parse import urlparse
from uuid import uuid4

from flask import Flask, jsonify, request, render_template
from flask_cors import CORS

from vrf import Vrf
from vdf import vdf_execute, vdf_verify, vdf_prime


# SEED for debugging
random.seed(666)

MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1

# Each difficulty is 4 zero bits on the hash target,
#   so 5*4=20 is good, but 6*4=24 is too many seconds for testing.
MINING_DIFFICULTY = 5
USE_PROOF_OF_TIME = True
TIME_MINING_DIFFICULTY = 10000
DEFAULT_DEBUG_STAKE = 25000
TOTAL_COINS = 100000


def raw_bytes(s):
    """Convert a string to raw bytes without encoding"""
    import struct

    out_list = []
    for cp in s:
        num = ord(cp)
        if num < 255:
            out_list.append(struct.pack('B', num))
        elif num < 65535:
            out_list.append(struct.pack('>H', num))
        else:
            b = (num & 0xFF0000) >> 16
            h = num & 0xFFFF
            out_list.append(struct.pack('>bH', b, h))
    return b''.join(out_list)


class Blockchain:

    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes = set()

        # Generate random number to be used as node_id
        self.node_id = str(uuid4()).replace('-', '')

        # Create genesis block
        genesis_block = self.create_append_block(0, '00')

        print('Initializing blockchain...')
        self.vrf = Vrf(keys=Vrf.create_rsa_keys())      # type: Vrf

    ########
    # NODES
    ########_b64

    def register_node(self, node_url):
        """
        Add a new node to the list of nodes
        """
        # Checking node_url has valid format
        parsed_url = urlparse(node_url)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    #######
    # TXS
    #######

    def submit_transaction(self, sender_address, recipient_address, value, signature):
        """
        Add a transaction to transactions array if the signature verified
        """
        transaction = \
            OrderedDict({
                            'sender_address': sender_address,
                            'recipient_address': recipient_address,
                            'value': value
                        })

        # Reward for mining a block
        if sender_address == MINING_SENDER:
            self.transactions.append(transaction)
            return len(self.chain) + 1

        # Manages transactions from wallet to another wallet
        else:
            transaction_verification = Blockchain.verify_transaction_signature(sender_address, signature, transaction)
            if transaction_verification:
                self.transactions.append(transaction)
                return len(self.chain) + 1
            else:
                return False

    @classmethod
    def verify_transaction_signature(cls, sender_address, signature, transaction):
        """
        Check that the provided signature corresponds to transaction
        signed by the public key (sender_address)
        """
        import binascii
        from Crypto.Hash import SHA
        from Crypto.PublicKey import RSA
        from Crypto.Signature import PKCS1_v1_5

        public_key = RSA.importKey(binascii.unhexlify(sender_address))
        verifier = PKCS1_v1_5.new(public_key)
        h = SHA.new(str(transaction).encode('utf8'))

        try:
            verifier.verify(h, binascii.unhexlify(signature))
            return True

        except ValueError:
            return False

    #########
    # BLOCKS
    #########

    def create_append_block(self, nonce, previous_hash, seed=None, miner_address=None):
        """
        Add a block of transactions to the blockchain
        """
        block = \
            {
                'block_number': len(self.chain) + 1,
                'timestamp': time(),
                'transactions': self.transactions,
                'nonce': nonce,
                'previous_hash': previous_hash
            }

        if USE_PROOF_OF_TIME:
            block['seed'] = seed
            block['miner_address'] = miner_address

        # Reset the current list of transactions
        self.transactions = []

        print('DEBUG: appending block ...')
        print(str(block))
        self.chain.append(block)
        return block

    ####################
    # VRF/VDF CONSENSUS
    ####################

    def proof_of_work(self):
        """
        Proof of work algorithm
        """
        last_block = self.chain[-1]
        last_hash = Blockchain.hash(last_block)

        nonce = 0
        while self.valid_proof(self.transactions, last_hash, nonce) is False:
            nonce += 1

        return nonce

    def proof_of_time(self):    # proof_of_random_time()
        """
        Proof of time algorithm
        """
        last_block = self.chain[-1]
        last_hash = Blockchain.hash(last_block)

        # VDF input
        vdf_input_integer = self.vdf_input(last_hash)

        # Calculate VDF Steps needed.

        # Adding VRF (WIP)
        node_vrf_seed_b64 = self.vrf.get_seed_b64(last_hash)

        vdf_difficulty = self.vdf_steps(DEFAULT_DEBUG_STAKE, TOTAL_COINS, node_vrf_seed_b64)
        print('VDF Difficulty = %d' % vdf_difficulty)
        
        print("DEBUG: Mining sequential VDF (Sloth) ...")
        # nonce = vdf_execute(vdf_input_integer,node_vdf_steps) # VRF version
        nonce = vdf_execute(vdf_input_integer, vdf_difficulty)
        print("DEBUG: Generated NONCE = %d" % nonce)

        return nonce, node_vrf_seed_b64, self.vrf.get_pem_public_key()      # , node_vrf_seed # with this

    def valid_proof(self, transactions, last_hash, nonce, block_number=None,
                          difficulty=MINING_DIFFICULTY, seed=None, miner_address=None):
        """
        Check if a hash value satisfies the mining conditions. This function is used within the proof_of_work function.
        """

        if block_number == 1 and nonce == 0:
            return True

        if not USE_PROOF_OF_TIME:   # use Proof-of-Work
            guess = (str(transactions)+str(last_hash)+str(nonce)).encode()
            guess_hash = hashlib.sha256(guess).hexdigest()
            return guess_hash[:difficulty] == '0'*difficulty

        else:
            print('DEBUG: checking valid_proof()...')

            if block_number is None:
                raise ValueError('When using proof_of_time consensus block_number must have value.')

            # Verify pseudorandom seed from miner with his public key.
            # Checking unique signature "seed" matches input "last_hash" if signed with private miner key.
            print('DEBUG: received VRF seed = %s' % seed)

            k_fruta = 20
            verified_vrf = self.vrf.verify(last_hash, seed, k_fruta, miner_address)
            print('DEBUG: verifying VRF -> %s' % str(verified_vrf))

            # Checking VDF Difficulty for block: we should use the Miner's Stake at the time of the validation.
            vdf_difficulty = self.vdf_steps(DEFAULT_DEBUG_STAKE, TOTAL_COINS, seed)
            print('VDF Difficulty = %d' % vdf_difficulty)

            y = nonce
            x = self.vdf_input(last_hash)
            t = vdf_difficulty                                              # TIME_MINING_DIFFICULTY
            print("DEBUG: Verifying VDF, Checking NONCE = %d" % nonce)

            verified_vdf = vdf_verify(y, x, t)
            print('DEBUG: verifying VDF -> %s' % str(verified_vdf))
            print("DEBUG: Valid Block = %s" % str(verified_vrf and verified_vdf))

            return verified_vrf and verified_vdf

    def valid_chain(self, chain: List[Dict[str, Union[str, slice]]]):
        """
        Check if a blockchain is valid
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            # print(last_block)
            # print(block)
            # print("\n-----------\n")
            # Check that the hash of the block is correct
            if block['previous_hash'] != Blockchain.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            # Delete the reward transaction
            transactions = block['transactions'][:-1]

            # Need to make sure that the dictionary is ordered. Otherwise we'll get a different hash
            transaction_elements = ['sender_address', 'recipient_address', 'value']
            transactions = \
                [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]

            print('DEBUG: calling valid_proof() with block:')
            print(str(block))
            print()
            if not self.valid_proof(transactions,
                                    block['previous_hash'],
                                    block['nonce'],
                                    block['block_number'],
                                    MINING_DIFFICULTY,
                                    block['seed'],
                                    block['miner_address']):
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

    def vdf_input(self, last_hash):

        print("DEBUG: TXs = %s" % str(self.transactions))
        print("DEBUG: last_hash = %s" % str(last_hash))

        vdf_input = (str(self.transactions) + str(last_hash)).encode()
        vdf_input_hash = hashlib.sha256(vdf_input).hexdigest()
        vdf_input_integer = int(vdf_input_hash, 16) % vdf_prime
        print("DEBUG: vdf_input_integer = %d" % vdf_input_integer)
        return vdf_input_integer  # , 0    # node_vrf_seed

    def vdf_steps(self, coins, total, seed_b64):
        seed_integer = self.vrf.os2ip(base64.b64decode(seed_b64))
        return stakes.vdfStepsByStakeDiscreteProtected(coins, total, seed_integer)

    def get_last_hash(self):
        last_block = self.chain[-1]
        last_hash = Blockchain.hash(last_block)
        return last_hash

    @classmethod
    def hash(cls, block):
        """
        Create a SHA-256 hash of a block
        """
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()

        return hashlib.sha256(block_string).hexdigest()


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
    transaction_result = blockchain.submit_transaction(values['sender_address'],
                                                       values['recipient_address'],
                                                       values['amount'],
                                                       values['signature'])
    if not transaction_result:
        response = {'message': 'Invalid Transaction!'}
        return jsonify(response), 406
    else:
        response = {'message': 'Transaction will be added to Block %s' % str(transaction_result)}
        return jsonify(response), 201


@app.route('/transactions/get', methods=['GET'])
def get_transactions():
    # Get transactions from transactions pool
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
        nonce, seed, miner_address = blockchain.proof_of_time()
    else:
        nonce = blockchain.proof_of_work()
        seed, miner_address = None, None

    # We must receive a reward for finding the proof.
    blockchain.submit_transaction(sender_address=MINING_SENDER,
                                  recipient_address=blockchain.node_id,
                                  value=MINING_REWARD,
                                  signature="")

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.create_append_block(nonce, previous_hash, seed, miner_address)

    response = {
        'message': "New Block Forged",
        'block_number': block['block_number'],
        'transactions': block['transactions'],
        'nonce': block['nonce'],
        'previous_hash': block['previous_hash'],
    }
    if USE_PROOF_OF_TIME:
        print('DEBUG: adding miner seed to response: ')
        print(str(block['seed']))
        response['seed'] = block['seed']
        print('DEBUG: adding miner address to response: ')
        print(str(block['miner_address']))
        response['miner_address'] = block['miner_address']

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
