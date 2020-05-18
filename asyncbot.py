#!/usr/bin/env python
import asyncio
import ssl
import time
from datetime import datetime
import config

def ssl_ctx():
	ctx = ssl.create_default_context()
	ctx.check_hostname = False
	ctx.verify_mode = ssl.CERT_NONE
	if config.cert.file:
	    ctx.load_cert_chain(config.cert.file, password=config.cert.password)
	return ctx

class IRC:
	def __init__(self):
		self.options = {
			'host'       : config.connection.server,
			'port'       : config.connection.port,
			'limit'      : 1024,
			'ssl'        : ssl_ctx() if config.connection.ssl else None,
			'family'     : 10 if config.connection.ipv6 else 2,
			'local_addr' : (config.connection.vhost, 0) if config.connection.vhost else None
		}
		self.reader  = None
		self.writer  = None

	def _raw(self, data):
		self.writer.write(data[:510].encode('utf-8') + b'\r\n')

	async def _connect(self):
		try:
			self.reader, self.writer = await asyncio.open_connection(**self.options)
			self._raw(f'USER {config.ident.username} 0 * :{config.ident.realname}')
			self._raw('NICK ' + config.ident.nickname)
		except Exception as ex:
			print(f'[!] - Failed to connect to IRC server! ({ex!s})')
		else:
			while not self.reader.at_eof():
				line = await self.reader.readline()
				if line:
					line = line.decode('utf-8').strip()
					args = line.split()
					#print(args)
					#print(len(args))
					if args[0] == 'PING':
						self._raw('PONG ' + args[1][1:])
						print('PONG ' + args[1][1:])
					elif args[1] == '001':
						self._raw('JOIN ' + config.connection.channel)
					elif 'KUSH' in line:
						self.missingchatter()

	async def missingchatter(self, interval):
		while True:
			await asyncio.sleep(interval)
			self._raw('NAMES ' + config.connection.channel)
			if len(args) >= 4 and args[3] == '=':
				chatternicklist = args[5:]
				for i in chatternicklist:
					self._raw('whois ' + i.replace('@','').replace('+',''))
			elif len(args) == 10 and args[9] == 'time':
				daysmissing = str(round(float(args[4]) / 86400, 2))
				if int(args[4]) >= int(2700):#2700 is about 48hours i believe???
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,4                                                  ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,4  1,8^^^^^^1,4  1,1   1,4 1,1     1,4 1,1  1,4  1,1  1,4 1,1  1,4   1,1   1,4 1,1 1,4  1,1  1,4 1,1  1,4  1,1   1,4 ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,4 1,8<0,2 **** 1,8>1,4 1,1 1,4 1,1 1,4 1,1 1,4 1,1 1,4 1,1 1,4 1,1 1,4 1,1 1,4 1,1 1,4  1,1 1,4 1,1 1,4  1,1 1,4 1,1 1,4 1,1 1,4  1,1 1,4  1,1 1,4 1,1 1,4  1,1 1,4  ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,4 1,8<0,2*CFLC*1,8>1,4 1,1   1,4 1,1 1,4 1,1 1,4 1,1 1,4 1,1  1,4  1,1  1,4 1,1  1,4   1,1   1,4 1,1 1,4  1,1  1,4 1,1  1,4   1,1 1,4  ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,4 1,8<0,2 **** 1,8>1,4 1,1 1,4 1,1 1,4 1,1 1,4   1,1 1,4 1,1 1,4 1,1 1,4 1,1 1,4  1,1 1,4 1,1 1,4  1,1 1,4 1,1 1,4 1,1 1,4  1,1 1,4  1,1 1,4 1,1 1,4  1,1 1,4  ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,4  1,8VVVVVV1,4  1,1 1,4 1,1 1,4 1,1 1,4   1,1 1,4 1,1  1,4  1,1  1,4 1,1 1,4 1,1 1,4  1,1 1,4 1,1 1,4 1,1  1,4 1,1  1,4 1,1 1,4 1,1 1,4  1,1 1,4  ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  1,1 1,10                  1,1 1,0   12NAME   1: ' + args[3] + '            ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  1,1 1,10 5,7,;\',;\',,5,10 1        1,1 1,0                            ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  1,1 1,10 5,7.;\'.  ( _5,10 1       1,1 1,0  12 AGE    1: 16 AND HALF     ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  1,1 1,10 5,7.1@5;;1  0O O 1,10       1,1 1,0                            ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  1,1 1,10 5,7.1 5; 1    > 1,10       1,1 1,0  12 HEIGHT1 : 5\' 12"          ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  1,1 1,10 5,7;1    5 ;;;;5,10  1     1,1 1,0                            ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  1,1 1,10 1,7      1,1___1,10 1,6\  1,10    1,1 1,0  12 WEIGHT1 : 330LBS 14(FNO) 1   ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  1,1 1,7          1,10 1,6  1,7   1,10  1,1 1,0                            ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  1,1 1,7     1,10         1,7   1,10 1,1 1,0   12EYES  1 : BROWN           ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  1,1                    1,0                            ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  Missing from #superbowl, SuperNETs for   ' + daysmissing + ' days ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  ANY INFORMATION REGARDING THE WHERE-ABOUTS OF   ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  THIS CHATTER SHOULD REPORT IT TO THE OFFICAL    ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  CENTER FOR LOST CHATTERS 14(CFLC)1 AS SOON AS OK.  ')
					self._raw('PRIVMSG ' + config.connection.channel + " :" + '1,0  1-800-5MISSING1                 missing@cflc.gov  ')
				
# Start
if __name__ == '__main__':
	Bot = IRC()
	asyncio.run(Bot._connect())
	asyncio.run(Bot.self.missingchatter(1*1))
	while True: # Keep-alive loop, since we are asyncronous
		input('')
