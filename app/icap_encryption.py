#!/bin/env python
# -*- coding: utf8 -*-
import datetime
import re
import threading
import os
import subprocess
import getpass
from hashlib import sha256
import hashlib
import base64
import xml.etree.ElementTree as et

try:
    import socketserver
except ImportError:
    import SocketServer

    socketserver = SocketServer

import sys

sys.path.append('.')

from .pyicap import *
from .object_crypto import AESCipher
from .aws_signature_icap import AWSSignature
from .auth_manager import AuthManager

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

class ThreadingSimpleServer(socketserver.ThreadingMixIn, ICAPServer):
    pass


class ICAPHandler(BaseICAPRequestHandler):
    pending_urls = {}

    def request_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', b'REQMOD')
        self.set_icap_header(b'Service', b'PyICAP Server 1.0')
        self.send_headers(False)

    def request_REQMOD(self):
        """
        fname = re.sub('\/', '_', self.enc_req[1].decode())
        f = open(fname, 'w')
        f.write('Request URL:\n')
        f.write(self.enc_req[1].decode())
        f.write('\n------------\n')
        f.write('Headers:\n')
        for i in self.enc_req_headers:
            f.write(i.decode() + " : ")
            for v in self.enc_req_headers[i]:
                f.write(v.decode() + ',')
            f.write('\n')

        f.close()
        """
        if not self.server.auth_manager.is_setup(): # Authentication manager is not set up
            self.send_error(403, message='error')
            return
        awss = AWSSignature()
        self.set_icap_response(200)

        self.set_enc_request(b' '.join(self.enc_req))
        for h in self.enc_req_headers:
            for v in self.enc_req_headers[h]:
                self.set_enc_header(h, v)

        content = b''
        if not self.has_body:
            if self.enc_req[0] == b'DELETE': # DeleteObject operation
                self.pending_urls[('DELETE', self.enc_req[1].decode())] = ''

            if self.enc_req[0] == b'PUT' and b'x-amz-copy-source' in self.enc_req_headers:
                # Object duplication, copy object key from existing record
                bucket_name = re.search("(?<=^\/)[^\/]+", self.enc_req_headers[b'x-amz-copy-source'][0].decode()).group()
                key = re.search("^.*\.s3.*\.amazonaws.com", self.enc_req[1].decode()).group() + \
                    re.search("(?<=^\/{})\/.*".format(bucket_name), self.enc_req_headers[b'x-amz-copy-source'][0].decode()).group()
                key = re.sub("(?<=^https:\/\/)[a-z0-9]+(?=.s3)", bucket_name, key)
                pending_entry = {
                    'source': key,
                    'new_path': self.enc_req[1].decode()
                }
                self.pending_urls[('PUT', self.enc_req[1].decode())] = pending_entry

            if self.enc_req[0] == b'POST' and b'?uploads' in self.enc_req[1]:
                # New multipart upload (CreateMultipartUpload)
                object_key = re.search("^.*(?=\?)", self.enc_req[1].decode()).group()
                self.pending_urls[('POST', self.enc_req[1].decode())] = {'multipart': 1,
                                                                'object_key': object_key}

            self.send_headers(False)
            return
        if self.preview:
            prevbuf = b''
            while True:
                chunk = self.read_chunk()
                if chunk == b'':
                    break
                prevbuf += chunk
            if self.ieof:
                self.send_headers(True)
                if len(prevbuf) > 0:
                    self.write_chunk(prevbuf)
                self.write_chunk(b'')
                return
            self.cont()
            self.send_headers(True)
            if len(prevbuf) > 0:
                self.write_chunk(prevbuf)
            while True:
                chunk = self.read_chunk()
                self.write_chunk(chunk)
                if chunk == b'':
                    break
        else:

            while True:  # Read request body
                chunk = self.read_chunk()
                content += chunk
                if chunk == b'':
                    break

            not_object_upload = re.search("\.s3\.(.+)\.amazonaws\.com/\?", self.enc_req[1].decode())
            is_multipart_upload = re.search("^.*\.s3\..*\.amazonaws.com\/.*\?partNumber=", self.enc_req[1].decode()) is not None
            complete_multipart_request = re.search("s3\..*\.amazonaws\.com\/.*\?uploadId=(?!.*partNumber=)",
                                                   self.enc_req[1].decode()) is not None
            if self.enc_req[0] == b'PUT' and not_object_upload is None and not is_multipart_upload:
                # Single object upload
                cp = AESCipher()
                enc_tup = cp.encrypt(content)
                encrypted_content_length = str(len(enc_tup[1])).encode()

                # Update these headers if they exist
                if b'content-md5' in self.enc_headers:
                    self.enc_headers.pop(b'content-md5')
                    encrypted_content_md5 = hashlib.md5(enc_tup[1]).hexdigest()
                    self.set_enc_header(b'content-md5', encrypted_content_md5.encode())
                elif b'x-amz-content-sha256' in self.enc_headers:
                    self.enc_headers.pop(b'x-amz-content-sha256')
                    encrypted_content_sha256 = sha256(enc_tup[1]).hexdigest()
                    self.set_enc_header(b'x-amz-content-sha256', encrypted_content_sha256.encode())

                self.enc_headers.pop(b'content-length')
                self.set_enc_header(b'content-length', encrypted_content_length)

                if b'content-type' in self.enc_headers:  # Binary files have no content-type header
                    self.enc_headers.pop(b'content-type')
                    self.set_enc_header(b'content-type', b'')

                content = enc_tup[1]
                key = enc_tup[0]
                #payload_hash = sha256(enc_tup[1]).hexdigest()

                sig = awss.gen_signature(request=self.enc_req, headers=self.enc_headers)  # Generate AWS signature
                self.set_enc_request(b'PUT ' + sig['url'].encode() + b' HTTP/1.1')  # Update URL of request

                if b'authorization' in self.enc_headers:
                    # Header should always be present if authenticating with header option
                    self.enc_headers.pop(b'authorization')
                    self.set_enc_header(b'authorization', sig['authorization-header'].encode())

                self.pending_urls[('PUT', sig['url'])] = {'key': key['key'], 'nonce': key['nonce'], 'tag': key['tag']}

            elif self.enc_req[0] == b'PUT' and is_multipart_upload:
                # Multipart upload
                cp = AESCipher()
                object_key = re.search("^.*\.s3\..*\.amazonaws.com\/.*(?=\?)", self.enc_req[1].decode()).group()
                part_num = re.search("(?<=partNumber=)[0-9]+", self.enc_req[1].decode()).group()
                upload_id = re.search("(?<=uploadId=)[^&]+", self.enc_req[1].decode()).group()
                file_params = self.server.auth_manager.get_object(object_key)  # Get key from existing record
                params_key = base64.b64decode(file_params.key)
                params_nonce = base64.b64decode(file_params.nonce)
                enc_tup = cp.encrypt(content, key=params_key, nonce=params_nonce)

                content = enc_tup[1]
                part_length = len(enc_tup[1])

                if b'content-md5' in self.enc_headers:
                    self.enc_headers.pop(b'content-md5')
                    encrypted_content_md5 = base64.b64encode(hashlib.md5(enc_tup[1]).digest())
                    self.set_enc_header(b'content-md5', encrypted_content_md5)
                if b'x-amz-content-sha256' in self.enc_headers:
                    self.enc_headers.pop(b'x-amz-content-sha256')
                    encrypted_content_sha256 = sha256(enc_tup[1]).hexdigest()
                    self.set_enc_header(b'x-amz-content-sha256', encrypted_content_sha256.encode())

                self.enc_headers.pop(b'content-length')
                self.set_enc_header(b'content-length', str(part_length).encode())

                if b'content-type' in self.enc_headers:  # binary files have no content-type header
                    self.enc_headers.pop(b'content-type')
                    self.set_enc_header(b'content-type', b'')

                sig = awss.gen_signature(request=self.enc_req, headers=self.enc_headers)
                self.set_enc_request(b'PUT ' + sig['url'].encode() + b' HTTP/1.1')
                if b'authorization' in self.enc_headers:
                    self.enc_headers.pop(b'authorization')
                    self.set_enc_header(b'authorization', sig['authorization-header'].encode())
                self.pending_urls[('PUT', sig['url'])] = { 'part_num': part_num,
                                                           'part_length': part_length,
                                                           'part_tag': enc_tup[0]['tag'],
                                                           'upload_id': upload_id
                                                           }

            elif self.enc_req[0] == b'POST' and complete_multipart_request is True:
                # Complete multipart upload request
                xmldata = et.fromstring(content.decode())
                valid_parts = xmldata.findall("./{*}Part/{*}PartNumber")
                valid_parts = [x.text for x in valid_parts]
                upload_id = re.search("(?<=\?uploadId=)([^\&]*)", self.enc_req[1].decode()).group()
                all_parts = self.server.auth_manager.get_object_parts(upload_id=upload_id)

                for part in all_parts:
                    # Remove invalid parts not referenced by CompleteMultiPartUpload
                    if str(part['part_num']) not in valid_parts:
                        self.server.auth_manager.delete_part(upload_id=upload_id, part_num=part['part_num'])

            self.send_headers(True)
            self.write_chunk(content)

    def response_OPTIONS(self):
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', b'RESPMOD')
        self.set_icap_header(b'Service', b'PyICAP Server 1.0')
        self.set_icap_header(b'Preview', b'0')
        self.set_icap_header(b'Transfer-Preview', b'*')
        self.set_icap_header(b'Transfer-Ignore', b'jpg,jpeg,gif,png,swf,flv')
        self.set_icap_header(b'Transfer-Complete', b'')
        self.set_icap_header(b'Max-Connections', b'100')
        self.set_icap_header(b'Options-TTL', b'3600')
        self.send_headers(False)

    def read_chunks(self):
        content = b''
        while True:
            chunk = self.read_chunk()
            content += chunk
            if chunk == b'':
                return content

    def response_RESPMOD(self):
        print("resp")
        obj = None
        self.set_icap_response(200)

        self.set_enc_status(b' '.join(self.enc_res_status))

        for h in self.enc_res_headers:
            for v in self.enc_res_headers[h]:
                self.set_enc_header(h, v)

        request_url = self.enc_req[1].decode()
        op = self.enc_req[0].decode()
        url = re.search("^.*\.(s3)\..*(\.amazonaws.com).*(?=\?)", self.enc_req[1].decode()) # Get object key
        if url is None:
            url = re.search("^.*\.(s3)\..*(\.amazonaws.com).*", self.enc_req[1].decode())

        print(self.enc_req)
        print("op: {} url: {}".format(op,url))
        if url is not None:
            url = url.group()
        else:
            url = request_url  # No object key

        if (op, request_url) in self.pending_urls.keys():
            obj = self.pending_urls.pop((op, request_url))

            if op == 'PUT' and 'part_num' not in obj: # Response for object upload (regular, not multipart)
                if re.search("\.s3\.(.+)\.amazonaws\.com/\?", request_url) is None:
                    if self.enc_res_status[1] == b'200':
                        if 'source' in obj:  # Upload/copy existing object
                            self.server.auth_manager.duplicate_object(object_path=obj['source'],
                                                                      new_object_path=obj['new_path'])
                        else:
                            self.server.auth_manager.add_object(
                                object_path=url,
                                object_key=obj['key'],
                                object_nonce=obj['nonce'],
                                object_tag=obj['tag']
                            )
                    else:
                        print("Received response not HTTP 200, will not store key for {}".format(obj['key']))

            elif op == 'PUT' and 'part_num' in obj:
                if self.enc_res_status[1] == b'200': # Part upload succeeded, add it to database
                    self.server.auth_manager.add_object_part(upload_id=obj['upload_id'], part_num=obj['part_num'], part_size=obj['part_length'], part_tag=obj['part_tag'])

            elif op == 'DELETE':
                self.server.auth_manager.delete_object(url)

        if not self.has_body:
            self.send_headers(False)
            return

        content = self.read_chunks()
        if self.preview and not self.ieof:
            self.cont()
            content = self.read_chunks()

        if op == 'GET':
            multipart_data = self.server.auth_manager.get_object_parts(url)
            if multipart_data is None:
                # Single object GET, not uploaded in parts
                obj_entry = self.server.auth_manager.get_object(object_path=url) # TODO: merge ops in single&multipart uploaded
                if obj_entry is not None: # GET response for known object
                    cp = AESCipher()
                    json_key = {'key': obj_entry.key, 'nonce': obj_entry.nonce, 'tag': obj_entry.tag}
                    content = cp.decrypt(json_key, content)
                else: # No object found in database
                    pass
            elif multipart_data is not None:
                # GET object uploaded in parts
                decrypted_content = b''
                obj_entry = self.server.auth_manager.get_object(object_path=url)

                index = 0
                for item in multipart_data:  # Decrypt each offset from database values
                    cp = AESCipher()
                    json_key = {'key': obj_entry.key, 'nonce': obj_entry.nonce, 'tag': item['part_tag']}
                    piece = content[index:index + item['part_size']]
                    decrypted_piece = cp.decrypt(json_key, piece)
                    decrypted_content += decrypted_piece
                    index += item['part_size']

                content = decrypted_content

        if op == 'POST':
            if re.search("\.s3\.(.+)\.amazonaws\.com/\?delete$", request_url) is not None:
                # Bucket paths starting with /? (no file key) are always non-upload config requests
                xmldata = et.fromstring(content.decode())
                for item in xmldata.findall("./{*}Deleted/{*}Key"):
                    key = request_url[:-7] + item.text
                    self.server.auth_manager.delete_object(key)

            elif obj is not None and 'multipart' in obj:  # Confirmed multipart upload initiated
                xmldata = et.fromstring(content.decode())
                upload_id = xmldata.find("./{*}UploadId").text
                self.server.auth_manager.new_multipart_upload(obj['object_key'], upload_id)

        self.send_headers(True)
        self.write_chunk(content)
        self.write_chunk(b'')


class S3_encryption_icap(object):

    def __init__(self, port, auth_manager):
        if port < 1024 or port > 65535:
            self.port = 1344
        else:
            self.port = port

        self.server = ThreadingSimpleServer((b'', self.port), ICAPHandler)
        self.server.auth_manager = auth_manager
        self.run = False

    def start_server(self):
        t = threading.current_thread()
        self.reload_squid()
        # Start handle request loop
        while getattr(t, "run", False):
            self.server.handle_request()

        print("stopped " + str(getattr(t, "run", "def")))

    def stop_server(self):
        self.server.shutdown()
        self.run = False

    def reload_squid(self): #Reload Squid process using system script
        script_path = os.path.join(BASE_DIR, "app/squid_reload.sh")
        try:
            subprocess.run(["sudo", script_path], check=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            print(e)
            print("Could not reload squid. Make sure user {} has non-interactive execute permission for {}".format(getpass.getuser(), script_path))
            return e.stderr

        return True
