from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver
import json
import cgi
import hashlib
from web3 import Web3
from eth_account import Account
from solc import compile_source
from web3.contract import ConciseContract
from web3.gas_strategies.time_based import medium_gas_price_strategy
from datetime import datetime, timedelta
import time
import re
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

w3 = Web3(Web3.WebsocketProvider('wss://ropsten.infura.io/ws/v3/8290d422df13434f8133c29fd2138734'))
acct = Account.privateKeyToAccount('BAD62390F4D3F53E67C70E3A4961D4724B7FF1BF66B2EF5486FFCC45A76F1806')
key = acct.privateKey

def sendInfoToOracle():
	info = acct.address
	hashedInfo = hashlib.sha256(info.encode('utf-8')).hexdigest() #Hash of json
	signedMessage = Account.signHash(hashedInfo, key)
	data = {
		"id" : 0,
		"address" : acct.address,
		"info" : info,
		"v" : signedMessage.v,
		"r" : signedMessage.r,
		"s" : signedMessage.s
	}
	headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
	r = requests.post("http://localhost:8008", data=json.dumps(data), headers=headers)
	print(r.json())

class MyHandler(FileSystemEventHandler):
	lineToRead = 0



	def findSid(self, sid):
		pattern = "sid:" + sid
		for i, line in enumerate(open('c:\\Snort\\rules\\local.rules')):
			for match in re.finditer(pattern, line):
				print("Found: " + sid)
				sendInfoToOracle()

	def getSid(self,line):
		parts = line.split(":")
		return parts[3]

	def readAddedLines(self, path):
		f = open(path)
		lines = f.readlines()
		newLines = lines[self.lineToRead:len(lines)]
		print(len(lines))
		for i in newLines:
			sid = self.getSid(i)
			self.findSid(sid)
		self.lineToRead = len(lines)

	def __init__(self):
		self.last_modified = datetime.now()

	def on_modified(self, event):
		print(time.time())	
		if datetime.now() - self.last_modified < timedelta(seconds=1):
			return
		else:
			self.last_modified = datetime.now()
		print(f'Event type: {event.event_type}  path : {event.src_path}')

		if event.src_path==".\\rules.txt":
			print(self.lineToRead)
			self.readAddedLines(event.src_path)
		   # checkRuleUsage(line[lineToRead])
		"""
		readNewLines()
		f = open(event.src_path)
		lines = f.readlines()
		print(len(lines))
		print(event.is_directory) # This attribute is also available
		"""

if __name__ == "__main__":
	event_handler = MyHandler()
	observer = Observer()
	observer.schedule(event_handler, path='.', recursive=False)
	observer.start()

	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		observer.stop()
	observer.join()
