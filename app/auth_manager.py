#!/usr/bin/python
import os
import base64
from Crypto.Cipher import AES
from app.models import ObjectEntry, MultipartUpload, MultipartData
from os.path import exists
import hashlib
from Crypto.Random import get_random_bytes

class AuthManager(object):
    
    _derived_password: bytearray = None
    _is_setup = False

    def __init__(self):
        if exists("credentials.bin"):
            self._is_setup = True

    def unlock(self, password):
        if self.is_setup():
            with open("credentials.bin", "rb") as f:
                stored_credentials = f.read().split(b'\x00' * 4)
                pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), stored_credentials[1], 100000)
                if stored_credentials[0] == pwd_hash:
                    derived_pass = hashlib.sha256()
                    derived_pass.update(password.encode())
                    self._derived_password = derived_pass.digest()
                    return True

        return False

    def lock(self):
        for i in range(len(self._derived_password)):
            self._derived_password[i] = 0

        print(self._derived_password)
        print(id(self._derived_password) )
        self._derived_password = None

    def is_setup(self):
        return self._is_setup

    def is_unlocked(self):
        return self._derived_password is not None

    def setup(self, password):
        salt = os.urandom(32)
        f = open("credentials.bin", "wb")
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        f.write(pwd_hash)
        f.write(b'\x00' * 4)
        f.write(salt)
        f.close()
        self._is_setup = True
        return True

    def add_object(self, object_path, object_key, object_nonce, object_tag):
        cipher = AES.new(self._derived_password, AES.MODE_SIV)
        cipher.update(b'')
        encrypted_key, encrypted_key_tag = cipher.encrypt_and_digest(object_key.encode())
        encrypted_key = base64.b64encode(encrypted_key).decode()
        encrypted_key_tag = base64.b64encode(encrypted_key_tag).decode()
        try: # Find existing record to update
            existing_file = ObjectEntry.objects.get(path=object_path)
            existing_file.key = encrypted_key
            existing_file.nonce = object_nonce
            existing_file.tag = object_tag
            existing_file.key_tag = encrypted_key_tag
            existing_file.save()
            return existing_file
        except ObjectEntry.DoesNotExist: # Create new object record
            new_entry = ObjectEntry(path=object_path, nonce=object_nonce, tag=object_tag, key=encrypted_key,
                                    key_tag=encrypted_key_tag)
            new_entry.save()
            return new_entry

    def new_multipart_upload(self, object_path, upload_id):
        key = base64.b64encode(get_random_bytes(32)).decode()
        nonce = base64.b64encode(get_random_bytes(16)).decode()
        self.add_object(object_path=object_path, object_key=key, object_nonce=nonce, object_tag='')

        try:
            existing_multipart_entry = MultipartUpload.objects.get(path=object_path)
            existing_multipart_entry.upload_id = upload_id
            existing_multipart_entry.save()

            # Delete previous parts
            MultipartData.objects.filter(upload_id=existing_multipart_entry).delete()
        except MultipartUpload.DoesNotExist:
            multipart_up = MultipartUpload()
            multipart_up.path = object_path
            multipart_up.upload_id = upload_id
            multipart_up.save()

    def add_object_part(self, upload_id, part_num, part_size, part_tag):
        multipart_upload = MultipartUpload.objects.get(upload_id=upload_id)
        upload_part = MultipartData(upload_id=multipart_upload, part_num=part_num, part_size=part_size, part_tag=part_tag)
        upload_part.save()

    def delete_part(self, upload_id, part_num):
        try:
            multipart_upload = MultipartUpload.objects.get(upload_id=upload_id)
            MultipartData.objects.filter(upload_id=multipart_upload, part_num=part_num).delete()
            return True
        except MultipartData.DoesNotExist:
            return False

    def get_object_parts(self, object_path=None, upload_id=None):
        out = []
        try:
            if object_path is not None:
                upload_id = MultipartUpload.objects.get(path=object_path)
            elif upload_id is not None:
                upload_id = MultipartUpload.objects.get(upload_id=upload_id)
            else:
                return None

            parts = MultipartData.objects.filter(upload_id=upload_id)
            for part in parts:
                out.append( {
                    'part_num': part.part_num,
                    'part_size': part.part_size,
                    'part_tag': part.part_tag,
                })
            return out
        except MultipartUpload.DoesNotExist:
            return None

    def duplicate_object(self, object_path, new_object_path):
        obj = ObjectEntry.objects.get(path=object_path)
        if obj is not None:
            try:
                existing_new_path = ObjectEntry.objects.get(path=new_object_path)
                existing_new_path.key = obj.key
                existing_new_path.nonce = obj.nonce
                existing_new_path.tag = obj.tag
                existing_new_path.key_tag = obj.key_tag
                existing_new_path.save()
                return True
            except ObjectEntry.DoesNotExist:
                obj.pk = None
                obj.path = new_object_path
                obj.save()
            return True
        else:
            return False

    def get_object(self, object_path):
        try: # Decrypt key for known object
            obj = ObjectEntry.objects.get(path=object_path)
            cipher = AES.new(self._derived_password, AES.MODE_SIV)
            cipher.update(b'')
            key = cipher.decrypt_and_verify(base64.b64decode(obj.key), base64.b64decode(obj.key_tag))
            obj.key = key
            return obj
        except ObjectEntry.DoesNotExist:  # Object does not exist, return error
            return None

    def get_multipart_upload(self, object_path):
        return MultipartUpload.objects.get(path=object_path)

    def delete_object(self, object_path):
        try:
            ObjectEntry.objects.get(path=object_path).delete()
            return True
        except ObjectEntry.DoesNotExist:
            return False
