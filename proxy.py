#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#
# Flying Proxy
#
# Copyright (c) 2001 Suzuki Hisao
# Copyright (c) 2009 Mitko Haralanov
# Copyright (c) 2013 Malte Bublitz
# 
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# 

__doc__ = """Flying Proxy

This module implements GET, HEAD, POST, PUT and DELETE methods
on BaseHTTPServer, and behaves as an HTTP proxy.  The CONNECT
method is also implemented experimentally, but has not been
tested yet.

Any help will be greatly appreciated.		SUZUKI Hisao

2009/11/23 - Modified by Mitko Haralanov
			 * Added very simple FTP file retrieval
			 * Added custom logging methods
			 * Added code to make this a standalone application
"""

__version__ = "0.3.4"
__ident__   = "FlyingProxy/"+__version__

import BaseHTTPServer, select, socket, SocketServer, urlparse
import logging
import logging.handlers
import getopt
import sys
import os
import signal
import threading
from types import FrameType, CodeType
from time import sleep
import ftplib
import base64
import ConfigParser

DEFAULT_LOG_FILENAME  = "proxy.log"
credentials           = "dGVzdDp0ZXN0" # test:test
do_override_useragent = False
user_agent            = __ident__
do_forward_socks      = False
socks_host            = ""
socks_port            = 0

def _quote_html(html):
	return html.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

class ProxyHandler (BaseHTTPServer.BaseHTTPRequestHandler):
	__base = BaseHTTPServer.BaseHTTPRequestHandler
	__base_handle = __base.handle

	server_version = __ident__
	rbufsize = 0						# self.rfile Be unbuffered

	def handle(self):
		(ip, port) =  self.client_address
		self.server.logger.log (logging.INFO, "Request from '%s'", ip)
		if hasattr(self, 'allowed_clients') and ip not in self.allowed_clients:
			self.raw_requestline = self.rfile.readline()
			if self.parse_request(): self.send_error(403)
		else:
			self.__base_handle()

	def checkAuth(self):
		global credentials
		auth = self.headers.get("Proxy-Authorization")
		if auth != "Basic "+base64.b64encode(credentials):
			self.send_response(407, "Authentication required")
			self.send_header("Proxy-Authenticate", "Basic realm=\""+__ident__+"\"")
			self.end_headers()
			return False
		return True
		
	def _connect_to(self, netloc, soc):
		i = netloc.find(':')
		if i >= 0:
			host_port = netloc[:i], int(netloc[i+1:])
		else:
			host_port = netloc, 80
		self.server.logger.log (logging.INFO, "connect to %s:%d", host_port[0], host_port[1])
		try: soc.connect(host_port)
		except socket.error, arg:
			try: msg = arg[1]
			except: msg = arg
			self.send_error(404, msg)
			return 0
		return 1

	def do_CONNECT(self):
		if not self.checkAuth():
			return
		global do_forward_socks
		global socks_host
		global socks_port
		if do_forward_socks:
			import socks
			soc = socks.socksocket()
			soc.setproxy(socks.PROXY_TYPE_SOCKS5, socks_host, socks_port)
		else:
			soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		
		try:
			if self._connect_to(self.path, soc):
				self.log_request(200)
				self.wfile.write(self.protocol_version +
								 " 200 Connection established\r\n")
				self.wfile.write("Proxy-agent: %s\r\n" % self.version_string())
				self.wfile.write("\r\n")
				self._read_write(soc, 300)
		finally:
			soc.close()
			self.connection.close()

	def do_GET(self):
		if not self.checkAuth():
			return
		(scm, netloc, path, params, query, fragment) = urlparse.urlparse(
			self.path, 'http')
		if scm not in ('http', 'ftp') or fragment or not netloc:
			self.send_error(400, "bad url %s" % self.path)
			return
		global do_forward_socks
		global socks_host
		global socks_port
		if do_forward_socks:
			import socks
			soc = socks.socksocket()
			soc.setproxy(socks.PROXY_TYPE_SOCKS5, socks_host, socks_port)
		else:
			soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			if scm == 'http':
				if self._connect_to(netloc, soc):
					self.log_request()
					soc.send("%s %s %s\r\n" % (self.command,
											   urlparse.urlunparse(('', '', path,
																	params, query,
																	'')),
											   self.request_version))
					self.headers['Connection'] = 'close'
					global do_override_useragent
					global user_agent
					if do_override_useragent:
						self.headers["User-Agent"] = user_agent
					del self.headers['Proxy-Connection']
					for key_val in self.headers.items():
						soc.send("%s: %s\r\n" % key_val)
					soc.send("\r\n")
					self._read_write(soc)
			elif scm == 'ftp':
				# fish out user and password information
				i = netloc.find ('@')
				if i >= 0:
					login_info, netloc = netloc[:i], netloc[i+1:]
					try: user, passwd = login_info.split (':', 1)
					except ValueError: user, passwd = "anonymous", None
				else: user, passwd ="anonymous", None
				self.log_request ()
				try:
					ftp = ftplib.FTP (netloc)
					ftp.login (user, passwd)
					if self.command == "GET":
						ftp.retrbinary ("RETR %s"%path, self.connection.send)
					ftp.quit ()
				except Exception, e:
					self.server.logger.log (logging.WARNING, "FTP Exception: %s",
											e)
		finally:
			soc.close()
			self.connection.close()

	def _read_write(self, soc, max_idling=20, local=False):
		iw = [self.connection, soc]
		local_data = ""
		ow = []
		count = 0
		while 1:
			count += 1
			(ins, _, exs) = select.select(iw, ow, iw, 1)
			if exs: break
			if ins:
				for i in ins:
					if i is soc: out = self.connection
					else: out = soc
					data = i.recv(8192)
					if data:
						if local: local_data += data
						else: out.send(data)
						count = 0
			if count == max_idling: break
		if local: return local_data
		return None

	do_HEAD = do_GET
	do_POST = do_GET
	do_PUT  = do_GET
	do_DELETE=do_GET

	def log_message (self, format, *args):
		self.server.logger.log (logging.INFO, "%s %s", self.address_string (),
								format % args)
		
	def log_error (self, format, *args):
		self.server.logger.log (logging.ERROR, "%s %s", self.address_string (),
								format % args)

	def send_error(self, code, message=None, netloc=None):
		try:
			msg_short, msg_long = self.responses[code]
		except KeyError:
			msg_short, msg_long = "???", "???"
		if message is None:
			message = msg_short
		explain = msg_long
		self.log_error("code %s, message %s", code, message)
		content = """<!DOCTYPE html>
<html>
	<head>
		<meta charset="UTF-8">
		<title>Error %(code)d</title>
		<style>
			div[role*=main] {
				width: 500px;
				margin: 3em auto;
			}
			h3 { font: 1.5em sans-serif; }
			div p { font: 1.2em sans-serif; }
		</style>
	</head>
	<body>
		<div role="main">
			<h3>Error %(code)d: %(message)s</h3>
			<p>
				%(explain)s
			</p>
		</div>
	</boody>
</html>""" % {'code': code, 'message': _quote_html(message), 'explain': explain}
		self.send_response(code, message)
		self.send_header("Content-Type", self.error_content_type)
		self.send_header("Connection", "close")
		self.end_headers()
		if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
			self.wfile.write(content)
class ThreadingHTTPServer (SocketServer.ThreadingMixIn,
						   BaseHTTPServer.HTTPServer):
	def __init__ (self, server_address, RequestHandlerClass, logger=None):
		BaseHTTPServer.HTTPServer.__init__ (self, server_address,
											RequestHandlerClass)
		self.logger = logger

def logSetup (filename, log_size, daemon):
	logger = logging.getLogger ("FlyingProxy")
	logger.setLevel (logging.ERROR)
	if not filename:
		if not daemon:
			# display to the screen
			handler = logging.StreamHandler ()
		else:
			handler = logging.handlers.RotatingFileHandler (DEFAULT_LOG_FILENAME,
															maxBytes=(log_size*(1<<20)),
															backupCount=5)
	else:
		handler = logging.handlers.RotatingFileHandler (filename,
														maxBytes=(log_size*(1<<20)),
														backupCount=5)
	fmt = logging.Formatter ("[%(asctime)-12s.%(msecs)03d] "
							 "%(levelname)-8s {%(name)s %(threadName)s}"
							 " %(message)s",
							 "%Y-%m-%d %H:%M:%S")
	handler.setFormatter (fmt)
		
	logger.addHandler (handler)
	return logger

def usage (msg=None):
	if msg: print msg
	print sys.argv[0], "[-p port] [-l logfile] [-c user:password] [-dh] [allowed_client_name ...]]"
	print
	print "   -p	   - Port to bind to"
	print "   -l	   - Path to logfile. If not specified, STDOUT is used"
	print "   -d	   - Run in the background"
	print "   -c      - Set user and password for authentication"
	print

def handler (signo, frame):
	while frame and isinstance (frame, FrameType):
		if frame.f_code and isinstance (frame.f_code, CodeType):
			if "run_event" in frame.f_code.co_varnames:
				frame.f_locals["run_event"].set ()
				return
		frame = frame.f_back
	
def daemonize (logger):
	class DevNull (object):
		def __init__ (self): self.fd = os.open ("/dev/null", os.O_WRONLY)
		def write (self, *args, **kwargs): return 0
		def read (self, *args, **kwargs): return 0
		def fileno (self): return self.fd
		def close (self): os.close (self.fd)
	class ErrorLog:
		def __init__ (self, obj): self.obj = obj
		def write (self, string): self.obj.log (logging.ERROR, string)
		def read (self, *args, **kwargs): return 0
		def close (self): pass
		
	if os.fork () != 0:
		## allow the child pid to instanciate the server
		## class
		sleep (1)
		sys.exit (0)
	os.setsid ()
	fd = os.open ('/dev/null', os.O_RDONLY)
	if fd != 0:
		os.dup2 (fd, 0)
		os.close (fd)
	null = DevNull ()
	log = ErrorLog (logger)
	sys.stdout = null
	sys.stderr = log
	sys.stdin = null
	fd = os.open ('/dev/null', os.O_WRONLY)
	#if fd != 1: os.dup2 (fd, 1)
	os.dup2 (sys.stdout.fileno (), 1)
	if fd != 2: os.dup2 (fd, 2)
	if fd not in (1, 2): os.close (fd)
	
def main ():
	cfg = ConfigParser.ConfigParser()
	cfg.read("proxy.ini")
	logfile = cfg.get("proxy", "logfile")
	if logfile == "None":
		logfile = None
	daemon  = cfg.get("proxy", "daemon")
	if daemon == "False":
		daemon = False
	else:
		daemon = True
	max_log_size = 20
	listen = cfg.get("proxy", "listen").split(":")
	ip = listen[0]
	port = int(listen[1])
	allowed = []
	global credentials
	credentials = cfg.get("proxy", "login")
	run_event = threading.Event ()
	local_hostname = socket.gethostname ()
	
	global do_override_useragent
	global user_agent
	do_override_useragent = cfg.get("proxy", "overrideUserAgent")
	if do_overrude_useragent:
		user_agent = cfg.get("proxy", "userAgent")
	
	global do_forward_socks
	global socks_host
	global socks_port
	do_forward_socks = cfg.get("proxy", "forwardToSOCKS")
	if do_forward_socks:
		import socks
		socks_host = cfg.get("proxy", "SOCKSHost")
		socks_port = int(cfg.get("proxy", "SOCKSPort"))
	
	try: opts, args = getopt.getopt (sys.argv[1:], "l:dhp:c:", [])
	except getopt.GetoptError, e:
		usage (str (e))
		return 1

	for opt, value in opts:
		if opt == "-p": port = int (value)
		if opt == "-l": logfile = value
		if opt == "-d": daemon = not daemon
		if opt == "-c": credentials = value
		if opt == "-h":
			usage ()
			return 0
		
	# setup the log file
	logger = logSetup (logfile, max_log_size, daemon)
	
	if daemon:
		daemonize (logger)
	signal.signal (signal.SIGINT, handler)
		
	if args:
		allowed = []
		for name in args:
			client = socket.gethostbyname(name)
			allowed.append(client)
			logger.log (logging.INFO, "Accept: %s (%s)" % (client, name))
		ProxyHandler.allowed_clients = allowed
	else:
		logger.log (logging.INFO, "Any clients will be served...")

	server_address = (ip, port)
	ProxyHandler.protocol = "HTTP/1.0"
	httpd = ThreadingHTTPServer (server_address, ProxyHandler, logger)
	sa = httpd.socket.getsockname ()
	print "Servering HTTP on", sa[0], "port", sa[1]
	req_count = 0
	while not run_event.isSet ():
		try:
			httpd.handle_request ()
			req_count += 1
			if req_count == 1000:
				logger.log (logging.INFO, "Number of active threads: %s",
							threading.activeCount ())
				req_count = 0
		except select.error, e:
			if e[0] == 4 and run_event.isSet (): pass
			else:
				logger.log (logging.CRITICAL, "Errno: %d - %s", e[0], e[1])
	logger.log (logging.INFO, "Server shutdown")
	return 0

if __name__ == '__main__':
	sys.exit (main ())
