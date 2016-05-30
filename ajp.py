import struct
from pprint import  pprint

# Some references:
# https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html

#global helpers
def pack_string(s):
	if s is None:
		return struct.pack(">h", -1)

	l = len(s)
	return struct.pack(">H%dsb" % l, l, s, 0)

def unpack(stream, fmt):
	size = struct.calcsize(fmt)
	buf = stream.read(size)
	return struct.unpack(fmt, buf)

def unpack_string(stream):
	size, = unpack(stream, ">h")
	if size == -1: # null string
		return None
	res, = unpack(stream, "%ds" % size)
	stream.read(1) # \0
	return res

class AjpForwardRequest(object):
	"""
	AJP13_FORWARD_REQUEST :=
		prefix_code	  (byte) 0x02 = JK_AJP13_FORWARD_REQUEST
		method		   (byte)
		protocol		 (string)
		req_uri		  (string)
		remote_addr	  (string)
		remote_host	  (string)
		server_name	  (string)
		server_port	  (integer)
		is_ssl		   (boolean)
		num_headers	  (integer)
		request_headers *(req_header_name req_header_value)
		attributes	  *(attribut_name attribute_value)
		request_terminator (byte) OxFF

	"""

	_, OPTIONS, GET, HEAD, POST, PUT, DELETE, TRACE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, ACL, REPORT, VERSION_CONTROL, CHECKIN, CHECKOUT, UNCHECKOUT, SEARCH, MKWORKSPACE, UPDATE, LABEL, MERGE, BASELINE_CONTROL, MKACTIVITY = range(28)

	# server == web server, container == servlet
	SERVER_TO_CONTAINER, CONTAINER_TO_SERVER = range(2)

	COMMON_HEADERS = ["SC_REQ_ACCEPT",
		"SC_REQ_ACCEPT_CHARSET", "SC_REQ_ACCEPT_ENCODING", "SC_REQ_ACCEPT_LANGUAGE", "SC_REQ_AUTHORIZATION", 
		"SC_REQ_CONNECTION", "SC_REQ_CONTENT_TYPE", "SC_REQ_CONTENT_LENGTH", "SC_REQ_COOKIE", "SC_REQ_COOKIE2",
		"SC_REQ_HOST", "SC_REQ_PRAGMA", "SC_REQ_REFERER", "SC_REQ_USER_AGENT"
	]

	ATTRIBUTES = ["context", "servlet_path", "remote_user", "auth_type", "query_string", "route", "ssl_cert", "ssl_cipher", "ssl_session", "req_attribute", "ssl_key_size", "secret", "stored_method"]

	def __init__(self, data_direction=None):
		self.prefix_code = 0x02
		self.method = None
		self.protocol = None   
		self.req_uri = None  
		self.remote_addr = None   
		self.remote_host = None
		self.server_name = None
		self.server_port = None
		self.is_ssl = None
		self.num_headers = None
		self.request_headers = None
		self.attributes = None

		self.data_direction = data_direction

	def pack_headers(self):
		"""
			req_header_name := 
				sc_req_header_name | (string)  [see below for how this is parsed]
			sc_req_header_name := 0xA0xx (integer)
			req_header_value := (string)


			accept  0xA001  SC_REQ_ACCEPT
			accept-charset  0xA002  SC_REQ_ACCEPT_CHARSET
			accept-encoding 0xA003  SC_REQ_ACCEPT_ENCODING
			accept-language 0xA004  SC_REQ_ACCEPT_LANGUAGE
			authorization   0xA005  SC_REQ_AUTHORIZATION
			connection  0xA006  SC_REQ_CONNECTION
			content-type	0xA007  SC_REQ_CONTENT_TYPE
			content-length  0xA008  SC_REQ_CONTENT_LENGTH
			cookie  0xA009  SC_REQ_COOKIE
			cookie2 0xA00A  SC_REQ_COOKIE2
			host	0xA00B  SC_REQ_HOST
			pragma  0xA00C  SC_REQ_PRAGMA
			referer 0xA00D  SC_REQ_REFERER
			user-agent  0xA00E  SC_REQ_USER_AGENT

			store headers as dict 
		"""
		self.num_headers = len(self.request_headers)

		res = ""
		res += struct.pack(">h", self.num_headers)
		for h_name in self.request_headers:
			if h_name.startswith("SC_REQ"):
				code = AjpForwardRequest.COMMON_HEADERS.index(h_name) + 1
				res += struct.pack("BB", 0xA0, code)
			else:
				res += pack_string(h_name)

			res += pack_string(self.request_headers[h_name])

		return res

	def pack_attributes(self):
		"""
			Information Code Value  Note
			?context	0x01	Not currently implemented
			?servlet_path   0x02	Not currently implemented
			?remote_user	0x03	
			?auth_type  0x04	
			?query_string   0x05	
			?route  0x06	
			?ssl_cert   0x07	
			?ssl_cipher 0x08	
			?ssl_session	0x09	
			?req_attribute  0x0A	Name (the name of the attribut follows)
			?ssl_key_size   0x0B	
			?secret 0x0C	
			?stored_method  0x0D	
			are_done	0xFF	request_terminator
		"""

		res = ""

		for attr in self.attributes:
			a_name = attr['name']
			code = AjpForwardRequest.ATTRIBUTES.index(a_name) + 1
			res += struct.pack("b", code)
			if a_name == "req_attribute":
				aa_name, a_value = attr['value']
				res += pack_string(aa_name)
				res += pack_string(a_value)
			else:
				res += pack_string(attr['value'])

		res += struct.pack("B", 0xFF)
		return res

	def serialize(self):
		res = ""

		res += struct.pack("bb", self.prefix_code, self.method)
		res += pack_string(self.protocol)
		res += pack_string(self.req_uri)
		res += pack_string(self.remote_addr)
		res += pack_string(self.remote_host)
		res += pack_string(self.server_name)
		res += struct.pack(">h", self.server_port)
		res += struct.pack("?", self.is_ssl)

		res += self.pack_headers()

		res += self.pack_attributes()

		if self.data_direction == AjpForwardRequest.SERVER_TO_CONTAINER:
			header = struct.pack(">bbh", 0x12, 0x34, len(res))
		else:
			header = struct.pack(">bbh", 0x41, 0x42, len(res))
		return header + res

	def parse(self, raw_packet):
		stream = StringIO(raw_packet)
		self.magic1, self.magic2, data_len = unpack(stream, "bbH")
		self.prefix_code, self.method = unpack(stream, "bb")
		self.protocol = unpack_string(stream)
		self.req_uri = unpack_string(stream)
		self.remote_addr = unpack_string(stream)
		self.remote_host = unpack_string(stream)
		self.server_name = unpack_string(stream)
		self.server_port = unpack(stream, ">h")
		self.is_ssl = unpack(stream, "?")
		self.num_headers, = unpack(stream, ">H")
		self.request_headers = {}
		for i in range(self.num_headers):
			code, = unpack(stream, ">H")
			if code > 0xA000:
				h_name = AjpForwardRequest.COMMON_HEADERS[code - 0xA001]
			else:
				h_name = unpack(stream, "%ds" % code)
				stream.read(1) # \0

			h_value = unpack_string(stream)

			self.request_headers[h_name] = h_value

class AjpResponse(object):
	"""
		AJP13_SEND_BODY_CHUNK := 
	  	  prefix_code   3
	  	  chunk_length  (integer)
	  	  chunk		*(byte)

		AJP13_SEND_HEADERS :=
	  	  prefix_code	   4
	  	  http_status_code  (integer)
	  	  http_status_msg   (string)
	  	  num_headers	   (integer)
	  	  response_headers *(res_header_name header_value)

		res_header_name := 
			sc_res_header_name | (string)   [see below for how this is parsed]

		sc_res_header_name := 0xA0 (byte)

		header_value := (string)

		AJP13_END_RESPONSE :=
	  	  prefix_code	   5
	  	  reuse			 (boolean)


		AJP13_GET_BODY_CHUNK :=
	  	  prefix_code	   6
	  	  requested_length  (integer)
	"""

	# prefix codes
	_,_,_,SEND_BODY_CHUNK, SEND_HEADERS, END_RESPONSE, GET_BODY_CHUNK = range(7)

	# send headers codes
	COMMON_SEND_HEADERS = [
			"Content-Type", "Content-Language", "Content-Length", "Date", "Last-Modified", 
			"Location", "Set-Cookie", "Set-Cookie2", "Servlet-Engine", "Status", "WWW-Authenticate"
			]

	def parse(self, stream):
		# read headers
		self.magic_1, self.magic_2, self.data_length = unpack(stream, ">bbH")

		self.prefix_code, = unpack(stream, "b")

		if self.prefix_code == AjpResponse.SEND_HEADERS:
			self.parse_send_headers(stream)
		elif self.prefix_code == AjpResponse.SEND_BODY_CHUNK:
			self.parse_send_body_chunk(stream)
		elif self.prefix_code == AjpResponse.END_RESPONSE:
			self.parse_end_response(stream)
		elif self.prefix_code == AjpResponse.GET_BODY_CHUNK:
			self.parse_get_body_chunk(stream)
		else:
			raise NotImplementedError

	def parse_send_headers(self, stream):
		self.http_status_code, = unpack(stream, ">H")
		self.http_status_msg = unpack_string(stream)
		self.num_headers, = unpack(stream, ">H")
		self.response_headers = {}
		for i in range(self.num_headers):
			code, = unpack(stream, ">H")
			if code <= 0xA000: # custom header
				h_name, = unpack(stream, "%ds" % code)
				stream.read(1) # \0
				h_value = unpack_string(stream)
			else:
				h_name = AjpResponse.COMMON_SEND_HEADERS[code-0xA001]
				h_value = unpack_string(stream)
			self.response_headers[h_name] = h_value

	def parse_send_body_chunk(self, stream):
		self.data = stream.read(self.data_length-1)

	def parse_end_response(self, stream):
		self.reuse, = unpack(stream, "b")

	def parse_get_body_chunk(self, stream):
		return


