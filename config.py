#!/usr/bin/env python
class connection:
	server  = 'irc.supernets.org'
	port    = 6667
	ipv6    = False
	ssl     = False
	vhost   = None
	channel = '#dev'
	key     = None

class cert:
	file     = None
	password = None

class ident:
	nickname = 'DEWGONG'
	username = 'DEWGONGS'
	realname = 'DEWGONGS'

class login:
	nickserv = None
	operator = None
