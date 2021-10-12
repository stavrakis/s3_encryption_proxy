#!/bin/python

import os
from decouple import config
import threading
import unittest
import datetime
import base64
import pytz
import requests
from hashlib import md5, sha256
import sys
import xml.etree.ElementTree as et

sys.path.append('.')
sys.path.append('./app')
import aws_signature_unit_tests

s3_bucket_name = "bucket17378"
region = "eu-west-2"

access_key = config('AWS_ACCESS_KEY')
secret_key = config('AWS_SECRET_KEY')


def thread_func(filename):
    data = b'a' * 50 * (1024 ** 2)
    print("generated file")
    filename = filename
    return _upload(data=data, filename=filename)


header_host = s3_bucket_name + '.s3.' + region + '.amazonaws.com'
bucket_url = "https://" + header_host
proxies = {
        "https": "http://192.168.1.116:3128",
        "http": "http://192.168.1.116:3128"
    }
awssig = aws_signature_unit_tests.AWSSignature()


def _upload(data, filename, use_proxy=True):  # If this breaks, use 2 date formats
    date = datetime.datetime.now(tz=pytz.UTC)
    date_8601 = date.strftime("%Y%m%d") + 'T' + date.strftime("%H%M%S") + 'Z'

    req_headers = {
        'host': header_host,
        'content-length': str(len(data)),
        'x-amz-content-sha256': sha256(data).hexdigest(),
        'content-type': '',
        'x-amz-storage-class': 'STANDARD',
        'x-amz-date': date_8601,
    }
    url = bucket_url + filename
    url = [b'PUT', url.encode(), b'HTTP/1.1']

    sig = awssig.gen_signature(request=url, headers=req_headers)
    req_headers['authorization'] = sig['authorization-header']

    print("final url: " + sig['url'])
    print("headers:")
    for key in req_headers:
        print(key + " : " + req_headers[key])

    if use_proxy:
        req = requests.put(url=sig['url'], data=data, headers=req_headers, proxies=proxies, verify="myCA.pem")
    else:
        req = requests.put(url=sig['url'], data=data, headers=req_headers)
    print(req.text)

    return req.status_code == 200


class UploadTestCase(unittest.TestCase):

    def test_1_upload(self):
        # Test a single object upload.
        data = b'a' * 4*(1024**2)
        print("generated file")
        filename = "/file_test.txt"
        self.assertTrue(_upload(data=data, filename=filename))

    def test_2_download(self):
        # Test a single object download. Use object from test 1 to verify downloaded object matches.
        url = "/file_test.txt"
        data = self._download(url)
        data_noproxy = self._download(url, use_proxy=False)

        if data is not False:
            self.assertTrue(data == b'This is a test\n')
            self.assertTrue(data != data_noproxy)
        else:
            self.fail()

    def test_3_delete(self):
        # Test object deletion. Key should not remain in bucket.
        result = self._delete("/file_test.txt")
        self.assertTrue(result)

        contents = self._listobjects()
        self.assertTrue("file_test.txt" not in contents.decode())

    def test_4_delete_multiple(self):
        # Test deletion via XML in POST request
        keys = []
        for i in range(0,3):
            data = b'File data ' + str(i).encode()
            key = 'md_file_{}'.format(i)
            key_slash = '/' + key
            upload = _upload(filename=key_slash, data=data)
            self.assertTrue(upload)
            keys.append(key)

        md_result = self._delete_multiple(keys)
        if md_result is False:
            self.fail("Error in request")
        elif "<Deleted>" in md_result.decode():
            self.assertTrue(True)
        else:
            self.fail()

    def test_5_delete_multiple_subdir(self):
        # Test proper parsing of subdirectories in object keys
        data = b'Data'
        files = ['root_file.txt', 'root2_file.txt', 'subfolder/subfolder_file.txt']
        for f in files:
            key_slash = '/' + f
            upload = _upload(filename=key_slash, data=data)
            self.assertTrue(upload)
        delete = self._delete_multiple(files)
        self.assertTrue(delete is not False)

    def test_6_non_upload_put_request_bypass(self):
        # Test other operations are correctly ignored
        date_8601 = self.date_now()
        body = b'<BucketLoggingStatus xmlns="http://doc.s3.amazonaws.com/2006-03-01" />'
        url = bucket_url + "/?logging"
        req = [b'PUT', url.encode(), b'HTTP/1.1']
        req_headers = {
            'host': header_host,
            'x-amz-date': date_8601,
            'content-length': str(len(body)),
            'x-amz-content-sha256': sha256(body).hexdigest(),
        }
        sig = awssig.gen_signature(request=req, headers=req_headers)
        req_headers['authorization'] = sig['authorization-header']
        print("logging url: {}".format(url))
        res = requests.put(url=url, data=body, headers=req_headers, proxies=proxies, verify="myCA.pem")
        self.assertTrue(res.status_code == 200)

    def test_7_copyobject(self):
        # Test object copying. New object must match the source when downloaded
        data = b'This is a test\n'
        filename = "/object_copy_test.txt"
        self.assertTrue(_upload(data=data, filename=filename))

        date_8601 = self.date_now()
        url = bucket_url + '/copied_object_test.txt'
        copy_source = '/' + s3_bucket_name + "/object_copy_test.txt"
        req_headers = {
            'host': header_host,
            'x-amz-date': date_8601,
            'x-amz-copy-source': copy_source,
            'x-amz-content-sha256': sha256(b'').hexdigest(),
        }
        req = [b'PUT', url.encode(), b'HTTP/1.1']
        sig = awssig.gen_signature(request=req, headers=req_headers)
        req_headers['authorization'] = sig['authorization-header']
        res = requests.put(url=url, headers=req_headers, proxies=proxies, verify="myCA.pem")
        self.assertTrue(res.status_code == 200)

        copied_object = self._download("/copied_object_test.txt")
        self.assertTrue(copied_object == data)

    def test_8_multipart(self):
        # Test multipart uploads. Create file, upload 3 chunks, discard 1. Check if result matches expected object data
        filename = "/partfile"
        print("getting random bytes...")
        f = os.urandom(11*1024**2)
        print("got random bytes")
        chunk1 = f[:5*1024**2]
        chunk2 = f[5*1024**2:10*1024**2]
        chunk3 = f[10*1024**2:]
        print("chunk 1 size: " + str(len(chunk1)) + ", chunk 2 size: " + str(len(chunk2)))
        date_8601 = self.date_now()
        url = bucket_url + filename + "?uploads"
        req_headers = {
            'host': header_host,
            'x-amz-date': date_8601,
            'x-amz-content-sha256': sha256(b'').hexdigest(),
        }
        req = [b'POST', url.encode(), b'HTTP/1.1']
        print("url: " + url)
        sig = awssig.gen_signature(request=req, headers=req_headers)
        req_headers['authorization'] = sig['authorization-header']

        res = requests.post(url=url, headers=req_headers, proxies=proxies, verify="myCA.pem")
        xmldata = et.fromstring(res.text)
        upload_id = xmldata.find("./{*}UploadId").text

        part_etags = {}
        part_num = 0
        for chunk in [chunk1, chunk2, chunk3]:
            part_num += 1
            date_8601 = self.date_now()
            url = bucket_url + filename + "?partNumber=" + str(part_num) + "&uploadId=" + upload_id
            req_headers = {
                'host': header_host,
                'x-amz-date': date_8601,
                'content-length': str(len(chunk)),
                'content-md5': str(base64.b64encode(md5(chunk).digest()), "utf-8"),
                'x-amz-content-sha256': sha256(chunk).hexdigest()
            }
            req = [b'PUT', url.encode(), b'HTTP/1.1']
            sig = awssig.gen_signature(request=req, headers=req_headers)
            req_headers['authorization'] = sig['authorization-header']
            res = requests.put(url=url, data=chunk, headers=req_headers, proxies=proxies, verify="myCA.pem")
            print(res.status_code)
            print(res.text)

            if chunk != chunk2:
                part_etags[part_num] = res.headers['ETag']

        url = bucket_url + filename + "?uploadId=" + upload_id
        data = "<CompleteMultipartUpload xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>"
        for partnum in part_etags:
            data += "<Part><ETag>{}</ETag><PartNumber>{}</PartNumber></Part>".format(part_etags[partnum], partnum)
        data += "</CompleteMultipartUpload>"
        data = data.encode()
        date_8601 = self.date_now()
        req_headers = {
            'host': header_host,
            'x-amz-date': date_8601,
            'x-amz-content-sha256': sha256(data).hexdigest(),
        }
        req = [b'POST', url.encode(), b'HTTP/1.1']
        sig = awssig.gen_signature(request=req, headers=req_headers)
        req_headers['authorization'] = sig['authorization-header']
        res = requests.post(url=url, data=data, headers=req_headers, proxies=proxies, verify="myCA.pem")
        self.assertTrue(res.status_code == 200)

        data = self._download("/partfile")
        if data is not False:
            self.assertTrue(data == chunk1 + chunk3)
        else:
            self.fail()

    def test_9_multithread(self):
        # Initiate multiple upload operations simultaneously
        threads = list()
        for i in range(10):
            filename = "/file" + str(i)
            x = threading.Thread(target=thread_func, args=(filename,))
            threads.append(x)
            x.start()
            dtnow = datetime.datetime.now()
            print("Thread {} started at {}".format(i, dtnow))

        for thr in threads:
            thr.join()


    def _delete(self, filename):
        # DeleteObject helper method
        date_8601 = self.date_now()
        req_headers = {
            'host': header_host,
            'x-amz-date': date_8601,
            'x-amz-content-sha256': sha256(b'').hexdigest()
        }

        url = bucket_url + filename
        req = [b'DELETE', url.encode(), b'HTTP/1.1']
        sig = awssig.gen_signature(request=req, headers=req_headers)
        req_headers['authorization'] = sig['authorization-header']
        res = requests.delete(url=url, headers=req_headers, proxies=proxies, verify='myCA.pem')
        return res.status_code == 204

    def _delete_multiple(self, keys):
        # DeleteObjects helper method
        body = "<?xml version='1.0' encoding='UTF-8'?><Delete xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>"
        for item in keys:
            append = "<Object><Key>{}</Key></Object>".format(item)

            body += append

        body += "</Delete>"
        body = body.encode()
        date = self.date_now()
        req_headers = {
            'host': header_host,
            'x-amz-date': date,
            'content-md5': str(base64.b64encode(md5(body).digest()), "utf-8"),
            'content-type': 'multipart/form-data',
            'content-length': str(len(body)),
            'x-amz-content-sha256': sha256(body).hexdigest()
        }

        url = bucket_url + "/?delete"
        req = [b'POST', url.encode(), b'HTTP/1.1']
        sig = awssig.gen_signature(request=req, headers=req_headers)
        req_headers['authorization'] = sig['authorization-header']
        res = requests.post(url=url, data=body, headers=req_headers, proxies=proxies, verify='myCA.pem')
        print(res.text)

        if res.status_code != 200:
            return False
        else:
            return res.content

    def _listobjects(self):
        # ListObjects helper method
        req_headers = {
            'host': header_host,
            'x-amz-date': self.date_now(),
            'x-amz-content-sha256': sha256(b'').hexdigest()
        }

        url = bucket_url + "/?list-type=2"
        req = [b'GET', url.encode(), b'HTTP/1.1']
        # print(req)
        sig = awssig.gen_signature(request=req, headers=req_headers)
        req_headers['authorization'] = sig['authorization-header']
        res = requests.get(url=url, headers=req_headers, proxies=proxies, verify='myCA.pem')
        return res.content

    def _download(self, file_key, use_proxy=True):
        # GetObject helper method
        url = bucket_url + file_key
        req_headers = {
            'host': header_host,
            'x-amz-date': self.date_now(),
            'x-amz-content-sha256': sha256(b'').hexdigest(),
        }
        req = [b'GET', url.encode(), b'HTTP/1.1']
        sig = awssig.gen_signature(request=req, headers=req_headers)
        req_headers['authorization'] = sig['authorization-header']

        if use_proxy:
            res = requests.get(url=url, headers=req_headers, proxies=proxies, verify="myCA.pem")
        else:
            res = requests.get(url=url, headers=req_headers)
        if res.status_code == 200:
            return res.content
        else:
            print(res.text)
            return False

    def date_now(self):
        date = datetime.datetime.now(tz=pytz.UTC)
        return date.strftime("%Y%m%d") + 'T' + date.strftime("%H%M%S") + 'Z'


if __name__ == '__main__':
    unittest.main()
