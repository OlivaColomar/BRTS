from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver,  json, cgi, hashlib, sys, os, struct, base64, time, threading, requests
from web3 import Web3
from eth_account import Account
from solc import compile_source
from web3.contract import ConciseContract
from web3.gas_strategies.time_based import medium_gas_price_strategy, fast_gas_price_strategy
from Crypto.Cipher import AES
from Crypto import Random
from pathlib import Path
import threading

ts1 = time.time()


#Import account from private key arguments.
try:
 	privateKey = sys.argv[1]
except IndexError:
	sys.exit("Error: Insert Private Key")


w3 = Web3(Web3.WebsocketProvider('wss://ropsten.infura.io/ws/v3/8290d422df13434f8133c29fd2138734'))
acct = Account.privateKeyToAccount(sys.argv[1])
key = acct.privateKey


abi = '''
[
	{
		"constant": false,
		"inputs": [
			{
				"name": "_myid",
				"type": "bytes32"
			},
			{
				"name": "_result",
				"type": "string"
			}
		],
		"name": "__callback",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_myid",
				"type": "bytes32"
			},
			{
				"name": "_result",
				"type": "string"
			},
			{
				"name": "_proof",
				"type": "bytes"
			}
		],
		"name": "__callback",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_customer",
				"type": "address"
			},
			{
				"name": "_hash",
				"type": "string"
			}
		],
		"name": "acceptPayment",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_hash",
				"type": "string"
			}
		],
		"name": "confirmReception",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [],
		"name": "initialPayment",
		"outputs": [],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_sender",
				"type": "address"
			},
			{
				"name": "_message",
				"type": "string"
			}
		],
		"name": "receiveInfo",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "amount",
				"type": "uint256"
			}
		],
		"name": "retrieveCustomerFunds",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "amount",
				"type": "uint256"
			}
		],
		"name": "retrieveOwnerFunds",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_customer",
				"type": "address"
			},
			{
				"name": "_key",
				"type": "string"
			}
		],
		"name": "sendKey",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"name": "_customer",
				"type": "address"
			},
			{
				"indexed": false,
				"name": "_hash",
				"type": "string"
			}
		],
		"name": "hashSent",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"name": "customerAddress",
				"type": "address"
			},
			{
				"indexed": false,
				"name": "rulesHash",
				"type": "string"
			},
			{
				"indexed": false,
				"name": "funds",
				"type": "uint256"
			}
		],
		"name": "hashAccepted",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": false,
				"name": "_customer",
				"type": "address"
			},
			{
				"indexed": false,
				"name": "_key",
				"type": "string"
			}
		],
		"name": "keySent",
		"type": "event"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "b",
		"outputs": [
			{
				"name": "",
				"type": "string"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "address"
			}
		],
		"name": "customerList",
		"outputs": [
			{
				"name": "customerAddress",
				"type": "address"
			},
			{
				"name": "funds",
				"type": "uint256"
			},
			{
				"name": "rulesHash",
				"type": "string"
			},
			{
				"name": "key",
				"type": "string"
			},
			{
				"name": "state",
				"type": "uint8"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"name": "",
				"type": "address"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "rulesPrice",
		"outputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "address"
			}
		],
		"name": "senderList",
		"outputs": [
			{
				"name": "senderAddress",
				"type": "address"
			},
			{
				"name": "isValue",
				"type": "bool"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "usagePrice",
		"outputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	}
]
'''

def makePayment():
	nonce = w3.eth.getTransactionCount(acct.address)
	estimatedGas = 200000
	rulesPrice = rulesContract.functions.rulesPrice().call()*2
	gasPrice = 2000000000
	transaction = rulesContract.functions.initialPayment().buildTransaction({
		'from': acct.address,
		'value': rulesPrice,
		'gas': estimatedGas,
		'gasPrice': gasPrice,
		'nonce': nonce,
		'chainId': 3 #Ropsten
		})			
	signed = w3.eth.account.signTransaction(transaction, key)
	tx_hash = w3.eth.sendRawTransaction(signed.rawTransaction)
	print(tx_hash)
	w3.eth.waitForTransactionReceipt(tx_hash)  



def sign():
	jsonString = json.dumps(data)
	hashJson = hashlib.sha256(jsonString.encode('utf-8')).hexdigest() #Hash of json
	signedMessage = Account.signHash(hashJson, key)

	data ['v'] = signedMessage.v
	data['r'] = signedMessage.r
	data['s'] = signedMessage.s
	print(data)


def decrypt_file(key, chunksize=24*1024):
	""" Decrypts a file using AES (CBC mode) with the
		given key. Parameters are similar to encrypt_file,
		with one difference: out_filename, if not supplied
		will be in_filename without its last extension
		(i.e. if in_filename is 'aaa.zip.enc' then
		out_filename will be 'aaa.zip')
	"""
	key = "0x" + key
	hex_int = int(key, 16)
	new_int = hex(hex_int)[2:]
	keyRecovered = bytes.fromhex(new_int)
	print(keyRecovered)
	with open("encryptedRules.txt", 'rb') as infile:
		origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
		iv = infile.read(16)
		decryptor = AES.new(keyRecovered, AES.MODE_CBC, iv)
		with open("rules.txt", 'wb') as outfile:
			while True:
				chunk = infile.read(chunksize)
				if len(chunk) == 0:
					break
				outfile.write(decryptor.decrypt(chunk))
			outfile.truncate(origsize)

def hashFile (in_filename, chunksize = 64*1024):
	hasher = hashlib.sha256()
	with open(in_filename, 'rb') as infile:
		while True:
			chunk = infile.read(chunksize)
			hasher.update(chunk)
			if(len(chunk)) == 0:
				hashedText = hasher.hexdigest()
				print(hashedText)
				break

#Event Handlers

def handle_hash_event(event, hashedFile):
	print(event)
	args = event['args']
	receiver = args['_customer']
	hashReceived = args['_hash']
	if hashReceived == hashedFile:
		confirmReception(hashedFile)
	else:
		print("Hash Incorrecto")

def wait_for_hash(hashedFile, hashFilter):
	print("Waiting for hash to be received from the blockchain...")
	monitor = True
	while monitor:
		for event in hashFilter.get_new_entries():
			monitor = handle_hash_event(event,hashedFile)
			time.sleep(poll_interval)

def handle_key_event(event):
	args = event['args']
	keyReceived = args['_key']
	decrypt_file(keyReceived)

def wait_for_key(keyFilter):
	print("Waiting for key to be received from the blockchain...")
	monitor = True
	while monitor:
		for event in keyFilter.get_new_entries():
			monitor = handle_key_event(event)
			time.sleep(poll_interval)


def hashFile (in_filename, chunksize = 64*1024):
	hasher = hashlib.sha256()
	with open(in_filename, 'rb') as infile:
		while True:
			chunk = infile.read(chunksize)
			hasher.update(chunk)
			if(len(chunk)) == 0:
				return hasher.hexdigest()
				
def confirmReception(hashedFile):
	estimatedGas = 200000
	nonce = w3.eth.getTransactionCount(acct.address)
	gasPrice = 1000000000
	transaction = rulesContract.functions.confirmReception(hashedFile).buildTransaction({
		'from': acct.address,
		'gas': estimatedGas,
		'gasPrice': gasPrice,
		'nonce': nonce,
		'chainId': 3 #Ropsten
		})			
	signed = w3.eth.account.signTransaction(transaction, key)
	tx_hash = w3.eth.sendRawTransaction(signed.rawTransaction)
	print(tx_hash)
	w3.eth.waitForTransactionReceipt(tx_hash)  




#Initialize Variables 
contractAddress = Web3.toChecksumAddress("0xcd793bf362647f0d5307e3a63fc7e87f7e490d08") #Contract address
rulesContract = w3.eth.contract(contractAddress,abi=abi)
#w3.eth.setGasPriceStrategy(fast_gas_price_strategy)
#gasPrice = w3.eth.generateGasPrice()
#print(gasPrice)
#Payment
makePayment()


#Signature
data = {
	"id": 0,
	"address": acct.address,
	"data": "Initial Request",
	"v": '',
	"r": '',
	"s": ''
}  

sign()

#Request

r = requests.post(url = "http://localhost:8008", json = data)

#Save encrypted rules file and get hash.
with open('encryptedRules.txt',"wb") as file:
	file.write(r.content)
	file.close()

hashedFile = hashFile("encryptedRules.txt")

#Wait for hash to be on blockchain
hashFilter = rulesContract.eventFilter('hashSent', {'fromBlock': 0,'toBlock': 'latest'});
poll_interval = 2
wait_for_hash(hashedFile, hashFilter)
keyFilter = rulesContract.eventFilter('keySent',{'fromBlock': 0,'toBlock': 'latest'})
wait_for_key(keyFilter)
ts2 = time.time()
print("Tiempo 1:")
print(ts1)
print("Tiempo 2:")
print(ts2)
print("Diferencia:")
print(ts2-ts1)
print("end")