from django.db import models


# Main table for object key storage
class ObjectEntry(models.Model):
    path = models.TextField()
    nonce = models.CharField(max_length=24)
    tag = models.CharField(max_length=24)
    key = models.CharField(max_length=44)
    key_tag = models.CharField(max_length=24)


# Multipart upload IDs
class MultipartUpload(models.Model):
    path = models.TextField()
    upload_id = models.TextField()
    parts = models.TextField()


# Multipart Upload part data
class MultipartData(models.Model):
    upload_id = models.ForeignKey('MultipartUpload', on_delete=models.CASCADE)
    part_num = models.IntegerField()
    part_size = models.BigIntegerField()
    part_tag = models.CharField(max_length=24)