from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver,  json, cgi, hashlib, sys, os, struct, base64, time, threading
from web3 import Web3
from eth_account import Account
from solc import compile_source
from web3.contract import ConciseContract
from web3.gas_strategies.time_based import medium_gas_price_strategy
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto import Random
from pathlib import Path
from datetime import datetime



w3 = Web3(Web3.WebsocketProvider('wss://ropsten.infura.io/ws/v3/8290d422df13434f8133c29fd2138734'))
acct = Account.privateKeyToAccount('BAD62390F4D3F53E67C70E3A4961D4724B7FF1BF66B2EF5486FFCC45A76F1806')
accountPrivateKey = acct.privateKey


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


def verifySignature(message):
	print("Verificando Firma")
	#get signature params
	v = int(message["v"])
	r = int(message ["r"])
	s = int(message["s"])
	address = message["address"]
	ecrecoverargs = (
	 v,
	 r,
	 s
	 )
	print(ecrecoverargs)
	#Clean params to compute hash.
	message['v'] = ''
	message['r'] = ''
	message['s'] = ''
	#Compute hash
	messageNoSign = message
	messageNoSign = json.dumps(messageNoSign)
	hashedMessage = hashlib.sha256(messageNoSign.encode('utf-8')).hexdigest()
	#Get address that signed the transaction
	addressSignature = Account.recoverHash(hashedMessage, ecrecoverargs)
	#Verify that address has enough funds to pay for rules.
	customer = rulesContract.functions.customerList(addressSignature).call()
	customerFunds = customer[1]
	rulesPrice = rulesContract.functions.rulesPrice().call()
	if customerFunds >= rulesPrice:
		print("Enough Funds")
		return True
	else:
		print("Not Enough Funds")
		return False


def hashFile (in_filename, chunksize = 64*1024):
	hasher = hashlib.sha256()
	with open(in_filename, 'rb') as infile:
		while True:
			chunk = infile.read(chunksize)
			hasher.update(chunk)
			if(len(chunk)) == 0:
				return hasher.hexdigest()



def encrypt_file (customer, in_filename, out_filename, chunksize=64*1024):
	random = Random.new()
	key = random.read(AES.key_size[0])
	print(key)
	iv = random.read(AES.block_size)
	encryptor = AES.new(key, AES.MODE_CBC, iv)
	filesize = os.path.getsize(in_filename)

	with open(in_filename, 'rb') as infile:
		with open(out_filename, 'wb') as outfile:
			outfile.write(struct.pack('<Q', filesize))
			outfile.write(iv)
			while True:
				chunk = infile.read(chunksize)
				chunk = chunk.decode("utf-8")
				print(chunk)
				if len(chunk) == 0:
					outfile.close()
					break
				elif len(chunk) % 16 != 0:
					chunk += ' ' * (16 - len(chunk) % 16)
				chunk = chunk.encode("utf-8")
				cipherText = encryptor.encrypt(chunk)
				outfile.write(cipherText)

	#Hash File and save key.
	hashedText = hashFile(out_filename)
	print(key)
	keyHex = key.hex()
	print(keyHex)
	date = datetime.now()
	dateString = date.strftime("%d/%m/%Y %H:%M:%S")
	data = dateString + " customer:" + customer + " key:" + keyHex + " hash:" + hashedText + "\n"
	with open("keys.txt", 'a') as keyfile:
		keyfile.write(data)

	# Send Hash to blockchain:
	nonce = w3.eth.getTransactionCount(acct.address)
	estimatedGas = 200000
	gasPrice = 2000000000
	transaction = rulesContract.functions.acceptPayment(customer ,hashedText).buildTransaction({
		'from': acct.address,
		'gas': estimatedGas,
		'gasPrice': gasPrice,
		'nonce': nonce,
		'chainId': 3 #Ropsten
		})			
	signed = w3.eth.account.signTransaction(transaction, accountPrivateKey)
	tx_hash = w3.eth.sendRawTransaction(signed.rawTransaction)
	print(tx_hash)

def searchKey(rulesHash):
	with open("keys.txt", 'rb') as file:
		content = file.read()
		content = content.decode("utf-8")
	matched_lines = [line for line in content.split('\r\n') if rulesHash in line]
	line = matched_lines[0]
	arguments = line.split(" ")
	key = arguments[3].split(":")[1]
	print(key)
	return key

def sendKey(funds, customerAddress, key):
	print("Printing Customer")
	print(customerAddress)
	print("Printing Key")
	print(key)
	customer = rulesContract.functions.customerList(customerAddress).call()
	customerFunds = customer[1]
	rulesPrice = rulesContract.functions.rulesPrice().call()
	if customerFunds >= rulesPrice:
		print("Enough Funds")
		# Send Hash to blockchain:
		nonce = w3.eth.getTransactionCount(acct.address)
		estimatedGas = 200000
		gasPrice = 2000000000
		transaction = rulesContract.functions.sendKey(customerAddress, key).buildTransaction({
			'from': acct.address,
			'gas': estimatedGas,
			'gasPrice': gasPrice,
			'nonce': nonce,
			'chainId': 3 #Ropsten
			})			
		signed = w3.eth.account.signTransaction(transaction, accountPrivateKey)
		tx_hash = w3.eth.sendRawTransaction(signed.rawTransaction)
		print(tx_hash)
	else:
		print("Not Enough Funds")



class Server(BaseHTTPRequestHandler):
		def _set_headers(self):
				self.send_response(200)
				self.send_header('Content-type', 'text/plain')
				self.send_header('Content-Disposition', 'attachment; filename="yourfilename.txt')
				self.end_headers()
				
		def do_HEAD(self):
				self._set_headers()


		def do_POST(self):
				print("Post Received")
				ctype, pdict = cgi.parse_header(self.headers['Content-Type'])
				
				# refuse to receive non-json content
				if ctype != 'application/json':
						self.send_response(400)
						self.end_headers()
						return
				# read json and verify signature
				length = int(self.headers['Content-Length'])
				message = self.rfile.read(length)
				message = message.decode("utf-8")
				message = json.loads(message) #message = dictionary
				customer = message["address"]
				if verifySignature(message):
					encrypt_file(customer,"rules.txt", "encryptedRules.txt")	
					message = json.dumps(message) #message = string
					message = str.encode(message)
					# send the message back
					self._set_headers()
					with open('encryptedRules.txt', 'rb') as file:
						self.wfile.write(file.read())


def run(server_class=HTTPServer, handler_class=Server, port=8008):
		server_address = ('', port)
		#w3.eth.setGasPriceStrategy(medium_gas_price_strategy)
		#gasPrice = w3.eth.generateGasPrice()
		#print(gasPrice)	
		httpd = server_class(server_address, handler_class)
		httpd.serve_forever()

def handle_confirmation_event(event):
	args = event['args']
	customer = args['customerAddress']
	customerString = ''.join(customer)
	rulesHash = args['rulesHash']
	funds = args['funds']
	key = searchKey(rulesHash)
	sendKey(funds, customerString, key)

def wait_for_confirmation(hashFilter):
	poll_interval = 2
	while True:
		for event in hashFilter.get_new_entries():
			handle_confirmation_event(event)
			time.sleep(poll_interval)

if __name__ == "__main__":
	
	contractAddress = Web3.toChecksumAddress("0xcd793bf362647f0d5307e3a63fc7e87f7e490d08") #Contract address
	rulesContract = w3.eth.contract(contractAddress,abi=abi)
	hashFilter = rulesContract.eventFilter('hashAccepted', {'fromBlock': 0,'toBlock': 'latest'});

	t = threading.Thread(target=run)
	t2 = threading.Thread(target=wait_for_confirmation, args=(hashFilter,))
	t.start()
	t2.start()
"""
	from sys import argv
		
	if len(argv) == 2:
			run(port=int(argv[1]))
	else:
			run()
"""