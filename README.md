# S3 Encryption Gateway

## General Info
This Django application performs transparent encryption/decryption of AWS S3 objects, by providing an ICAP server and key management. Proxy software (e.g. Squid) is required to intercept S3 traffic and forward it via ICAP. Objects are encrypted using AES-256-GCM. Keys are stored in local SQLite database, encrypted using AES-256-SIV with a master password.
Object cryptography and key storage are managed by this software, so no keys are transmitted to S3, nor is any S3 encryption feature used. This gateway can be adapted for systems using cloud storage services that do not offer encryption.
## Features
* PutObject Modification: Requests are modified to encrypt object in the request body, and replace authorization signature in the HTTP headers with a valid one for the new (encrypted) object checksum.
* GetObject Modification: Server responses for objects uploaded via this gateway are modified to decrypt the received object in the response body.
* Object copy: Duplicates credentials for object-copy operations
* Multipart uploads: Supports encryption for multipart uploads with discarded parts. While parts can be discarded, valid ones must be uploaded in order.

## Requirements
* Squid built with [SSL support](https://wiki.squid-cache.org/ConfigExamples/Intercept/SslBumpExplicit) and configured for [SSL Bumping](https://wiki.squid-cache.org/Features/SslBump):
```
./configure \
    --with-openssl \
    --enable-ssl-crtd
```
* [pyicap](https://github.com/netom/pyicap/)
* AWS credentials for signing requests

## Usage
* Create .env file in django project root (where manage.py is) with this content:
```
SECRET_KEY=<your Django secret key>
AWS_ACCESS_KEY=<AWS access key>
AWS_SECRET_KEY=<AWS secret key>
```
* Start django application (./manage.py runserver) and navigate to <server_address\>/s3_proxy
* Enter desired master password for setup, or previously entered password to unlock database
* Start/restart Squid process
* Configure S3 client to use squid's listening address, and trust squid's certificate