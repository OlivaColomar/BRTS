from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver
import json
import cgi
import hashlib
import time
from web3 import Web3
from eth_account import Account
from solc import compile_source
from web3.contract import ConciseContract
from web3.gas_strategies.time_based import medium_gas_price_strategy

w3 = Web3(Web3.WebsocketProvider('wss://ropsten.infura.io/ws/v3/8290d422df13434f8133c29fd2138734'))
acct = Account.privateKeyToAccount('BAD62390F4D3F53E67C70E3A4961D4724B7FF1BF66B2EF5486FFCC45A76F1806')
key = acct.privateKey

abi = '''
[
	{
		"constant": true,
		"inputs": [],
		"name": "nextIDSource",
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
		"name": "receivers",
		"outputs": [
			{
				"name": "contractAddress",
				"type": "address"
			},
			{
				"name": "ownerAddress",
				"type": "address"
			},
			{
				"name": "funds",
				"type": "uint256"
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
		"constant": false,
		"inputs": [
			{
				"name": "_estimatedGas",
				"type": "uint256"
			},
			{
				"name": "_idSource",
				"type": "uint256"
			},
			{
				"name": "_receiver",
				"type": "address"
			},
			{
				"name": "_information",
				"type": "string"
			},
			{
				"name": "_v",
				"type": "uint8"
			},
			{
				"name": "_r",
				"type": "bytes32"
			},
			{
				"name": "_s",
				"type": "bytes32"
			}
		],
		"name": "sendInformation",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_contractAddress",
				"type": "address"
			}
		],
		"name": "addFunds",
		"outputs": [],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_name",
				"type": "string"
			},
			{
				"name": "_informationStructure",
				"type": "string"
			}
		],
		"name": "registerSource",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "oracleFunds",
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
				"name": "_receiver",
				"type": "address"
			}
		],
		"name": "getReceiverFunds",
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
		"constant": false,
		"inputs": [
			{
				"name": "_contractAddress",
				"type": "address"
			}
		],
		"name": "registerReceiver",
		"outputs": [],
		"payable": true,
		"stateMutability": "payable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [
			{
				"name": "",
				"type": "uint256"
			}
		],
		"name": "sources",
		"outputs": [
			{
				"name": "id",
				"type": "uint256"
			},
			{
				"name": "name",
				"type": "string"
			},
			{
				"name": "informationStructure",
				"type": "string"
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
		"name": "oracleOwner",
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
		"inputs": [
			{
				"name": "_id",
				"type": "uint256"
			}
		],
		"name": "getReceivers",
		"outputs": [
			{
				"name": "",
				"type": "address[]"
			}
		],
		"payable": false,
		"stateMutability": "view",
		"type": "function"
	},
	{
		"constant": false,
		"inputs": [
			{
				"name": "_contractAddress",
				"type": "address"
			},
			{
				"name": "_idSource",
				"type": "uint256"
			}
		],
		"name": "subscribeToSource",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "realFunds",
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
		"constant": false,
		"inputs": [],
		"name": "getRealFunds",
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
		"name": "retrieveFunds",
		"outputs": [],
		"payable": false,
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"payable": true,
		"stateMutability": "payable",
		"type": "constructor"
	}
]
'''

def to_32byte_hex(val):
	return Web3.toHex(Web3.toBytes(val).rjust(32, b'\0'))

def sendInformation(id, message, v, r, s):

	nonce = w3.eth.getTransactionCount(acct.address)
	contractAddress = Web3.toChecksumAddress("0xa19379b9d8a4436c078e112d27072fdc211eda3e") #Contract address
	oracleContract = w3.eth.contract(contractAddress,abi=abi)
	receivers = oracleContract.functions.getReceivers(id).call()
	for receiver in receivers:
		funds = oracleContract.functions.getReceiverFunds(receiver).call() 
		estimatedGas = 300000 #Estimate gas. Currently not working.
		#w3.eth.setGasPriceStrategy(medium_gas_price_strategy)
		gasPrice = 1000000000
		print(gasPrice)
		print(receiver)
		#if(funds>gasPrice*estimatedGas):
		print(message)
		transaction = oracleContract.functions.sendInformation(estimatedGas, id, receiver, message, v, to_32byte_hex(r), to_32byte_hex(s)).buildTransaction(
		{'from': acct.address,
		'gas': 1000000,
		'gasPrice': gasPrice,
		'nonce': nonce,
		'chainId': 3}
		)
		signed = w3.eth.account.signTransaction(transaction, key)
		tx_hash = w3.eth.sendRawTransaction(signed.rawTransaction)
		print(tx_hash)
		nonce += 1
		w3.eth.waitForTransactionReceipt(tx_hash) #no indent  

def verifySignature(message):
	print("Verificando Firma")
	sourceID = int(message["id"])
	print(sourceID)
	#get signature params
	v = int(message.pop("v",None))
	r = int(message.pop("r",None))
	s = int(message.pop("s",None))
	info = message["info"]
	address = message["address"]
	print(message)
	ecrecoverargs = (
	 v,
	 r,
	 s
	 )
	print(ecrecoverargs)
	#Compute hash
	hashedMessage = hashlib.sha256(info.encode('utf-8')).hexdigest()
	#Verify Signature
	addressSignature = Account.recoverHash(hashedMessage, ecrecoverargs)
	print(addressSignature)
	print(address)
	if(addressSignature == address): #Signature is correct
		print("Firma Correcta")
		sendInformation(sourceID, info, v, r, s)
	else:
		print("Firma Incorrecta")
	
		
class Server(BaseHTTPRequestHandler):
		def _set_headers(self):
				self.send_response(200)
				self.send_header('Content-type', 'application/json')
				self.end_headers()
				
		def do_HEAD(self):
				self._set_headers()


		# POST echoes the message adding a JSON field
		def do_POST(self):
				ts1 = time.time()
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
				print(message)
				verifySignature(message)
				message = json.dumps(message) #message = string
				message = str.encode(message)

				# send the message back
				self._set_headers()
				self.wfile.write(message)
				print(time.time()-ts1)


def run(server_class=HTTPServer, handler_class=Server, port=8008):
		server_address = ('', port)
		httpd = server_class(server_address, handler_class)
		httpd.serve_forever()
		
if __name__ == "__main__":
		from sys import argv
		
		if len(argv) == 2:
				run(port=int(argv[1]))
		else:
				run()
