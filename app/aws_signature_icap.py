import sys
import re
import hmac
from decouple import config
from urllib.parse import quote
from hashlib import sha256


class AWSSignature(object):	
	
	access_key_id = config('AWS_ACCESS_KEY')
	secret_access_key = config('AWS_SECRET_KEY')
	
	def gen_signature(self, request=None, headers=None):
		if request is None or headers is None:
			return False

		# URL header modification was deprecated in favour of HTTP header modification
		self.url = re.search("^.*\?", request[1].decode())
		if self.url is None:
			self.url = request[1].decode()
			self.useURLQuery = False
		elif re.search(".amazonaws.com/\?", request[1].decode()) is not None:
			self.url = re.search("^.*(?=\/\?)", request[1].decode()).group()
			self.useURLQuery = False
		elif re.search("\?uploads", request[1].decode()) is not None:
			self.url = re.search("^.*(?=\?)", request[1].decode()).group()
			self.useURLQuery = False
		else:
			self.url = request[1].decode()
			self.useURLQuery = False


		self.bucketname = re.search("(?<=https\:\/\/).+?(?=\.s3)", request[1].decode()).group()
		if self.useURLQuery is True:
			self.path = re.search("(?<=amazonaws\.com).*(?=\?)", request[1].decode()).group()
			self.canonical_query_string = re.search("(?<=\?)(.*)(?=\&X-Amz-Signature)", request[1].decode()).group()
		else:
			self.path = re.search("(?<=amazonaws\.com).*", request[1].decode()).group()
			self.canonical_query_string = ""
			if self.path.startswith("/?"):
				self.canonical_query_string = self.path[2:] + '='
				self.path = '/'
			if self.path.endswith("?uploads"):
				self.canonical_query_string = "uploads="
				self.path = self.path[:-8]
			else: # made for uploadpart case, will append everything after ? to canonical query line
				regex = re.search("(?<=amazonaws\.com).*(?=\?)", request[1].decode())
				if regex is not None:
					self.path = regex.group()
					self.canonical_query_string = re.search("(?<=\?).*", request[1].decode()).group()
				else:
					self.path = re.search("(?<=amazonaws\.com).*", request[1].decode()).group()
					self.canonical_query_string = ""

		self.canonical_uri = self.path

		self.canonical_headers_host = "host:" + re.search("(?<=https\:\/\/).*(.amazonaws.com)", request[1].decode()).group()
		self.canonical_headers_x_amz_headers = []
		self.signed_headers = ["host"]
		for h in headers:
			if h.startswith(b'x-amz') or h == b'content-md5' or h == b'content-type':
				self.canonical_headers_x_amz_headers.append(h.decode() + ":" + headers[h][0].decode() + "\n")
				self.signed_headers.append(h.decode())
		
		self.signed_headers.sort()
		self.canonical_headers = [self.canonical_headers_host] + self.canonical_headers_x_amz_headers
		self.canonical_headers.sort()
		self.canonical_headers_string = ""
		for i in self.canonical_headers:
			self.canonical_headers_string += i
			if self.canonical_headers_string[-1] != "\n":
				self.canonical_headers_string += "\n"
		self.canonical_headers_string = self.canonical_headers_string[:-1]

		self.signed_headers_string = ""
		for sh in self.signed_headers:
			self.signed_headers_string += sh + ";"
		
		self.signed_headers_string = self.signed_headers_string[:-1]

		self.signedheaders_uriencoded = quote(self.signed_headers_string)
		self.canonical_query_string = re.sub("(X-Amz-SignedHeaders\=).*(?=\&)", "X-Amz-SignedHeaders=" + self.signedheaders_uriencoded, self.canonical_query_string)
		self.canonical_query_string = re.sub("(X-Amz-Security-Token).+?(\&)", "", self.canonical_query_string)


		self.canonical_query_string = re.sub("(?<=X\-Amz\-Credential\=).+?(?=\%2F)", self.access_key_id, self.canonical_query_string)

		if self.useURLQuery:
			self.canonical_query_list = self.canonical_query_string.split("&")
			self.canonical_query_list.sort()
			self.canonical_query_string = ""
			for i in self.canonical_query_list:
				self.canonical_query_string += i + "&"
			self.canonical_query_string = self.canonical_query_string[:-1]

		if b'x-amz-date' in headers:
			self.timestamp = headers[b'x-amz-date'][0].decode()
		else:
			self.timestamp = re.search("(?<=X-Amz-Date\=)[0-9A-Z]*(?=\&)", request[1].decode()).group()

		self.aws_region = re.search("(?<=s3\.).*(?=\.amazonaws.com)", self.canonical_headers_host).group()
		self.date = re.search("^.*(?=T)", self.timestamp).group()
		self.scope = self.date + "/" + self.aws_region + "/" + "s3" + "/aws4_request"
		
		self.canonical_request = request[0].decode() + "\n" + self.canonical_uri + "\n" + self.canonical_query_string + "\n" + self.canonical_headers_string + "\n\n" + self.signed_headers_string + "\n"
		if b'x-amz-content-sha256' in headers:
			self.canonical_request += headers[b'x-amz-content-sha256'][0].decode()
		else:
			self.canonical_request += "UNSIGNED-PAYLOAD"

		self.canonical_request_hash = sha256(self.canonical_request.encode()).hexdigest()
		self.string_to_sign = "AWS4-HMAC-SHA256" + "\n" + self.timestamp + "\n" + self.scope + "\n" + self.canonical_request_hash

		self.sig_datekey = hmac.new(b'AWS4' + self.secret_access_key.encode(), self.date.encode(), sha256).digest()
		self.sig_dateregionkey = hmac.new(self.sig_datekey, self.aws_region.encode(), sha256).digest()
		self.sig_dateregionservicekey = hmac.new(self.sig_dateregionkey, b's3', sha256).digest()
		self.sig_signingkey = hmac.new(self.sig_dateregionservicekey, b'aws4_request', sha256).digest()
		
		self.signature = hmac.new(self.sig_signingkey, self.string_to_sign.encode(), sha256).hexdigest()

		if self.useURLQuery is True:
			self.canonical_query_string += "&X-Amz-Signature=" + self.signature

		self.authorization_header = 'AWS4-HMAC-SHA256 Credential={}/{}/{}/s3/aws4_request'.format(self.access_key_id,self.date,self.aws_region)
		self.authorization_header += ',SignedHeaders={}'.format(self.signed_headers_string)
		self.authorization_header += ',Signature={}'.format(self.signature)
		self.out = {}
		self.out['signature'] = self.signature
		self.out['query_string'] = self.canonical_query_string
		self.out['url'] = self.url #+ self.canonical_query_string
		self.out['authorization-header'] = self.authorization_header

		return self.out

#if __name__ == "__main__":
#	c = AWSSignature()
#	out = c.gen_signature()
#	print("sig = " + out['signature'])
