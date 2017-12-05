#!/usr/bin/env python
# encoding: utf-8

from mssapi.exception import MssapiServerError
from mssapi.s3.connection import S3Connection

import os
import hashlib


MSS_HOST = os.getenv('MSS_HOST')
MSS_ACCESS_KEY = os.getenv('MSS_ACCESS_KEY')
MSS_ACCESS_SECRET = os.getenv('MSS_SECRET_KEY')

assert MSS_HOST and MSS_ACCESS_KEY and MSS_ACCESS_SECRET


def mss_test_get_bucket(conn, name):
    b0 = None
    try:
        b0 = conn.get_bucket(name)
    except MssapiServerError as e:
        if e.error_code == 'NoSuchBucket':
            b0 = conn.create_bucket(name)
        else:
            raise e
    return b0

def mss_test_range_prepare(filename, size):
    hash_md5 = hashlib.md5()
    with open(filename, 'wb') as fp:
        offset = 0
        while offset < size:
            part_size = min(1024*1024, size - offset)
            bytes = part_size * 'a'
            fp.write(bytes)
            offset += part_size
            hash_md5.update(bytes)
    return hash_md5.hexdigest()

def mss_range_download():
    filename = "range_test.origin"
    conn = S3Connection(aws_access_key_id=MSS_ACCESS_KEY, aws_secret_access_key=MSS_ACCESS_SECRET, host=MSS_HOST)
    b0 = mss_test_get_bucket(conn, 'example')

    #prepare
    print 'prepare file...'
    file_md5 = mss_test_range_prepare(filename, 3*1024*1024)

    # upload
    print 'upload file...'
    k0 = b0.new_key('range_test.mss')
    k0.set_contents_from_filename(filename)

    # download
    k0_download = b0.get_key('range_test.mss')
    assert k0_download is not None

    print 'download file with HTTP Range Request...'
    hash_md5 = hashlib.md5()
    offset = 0
    with open('multipart-test.txt.dowload', 'wb') as fp:
        while offset < k0_download.size:
            size = min(1024*1024, k0.size - offset)
            try:
                bytes = k0_download.get_contents_as_string(headers={'Range': 'bytes=%d-%d' % (offset, offset + size - 1)})
            except:
                k0_download.close()
                raise
            fp.write(bytes)
            offset += size
            hash_md5.update(bytes)

    print 'check file md5...'
    assert k0.etag.strip('"') == hash_md5.hexdigest()
    assert k0.etag == k0_download.etag
    assert k0.etag.strip('"') == file_md5

    os.remove(filename)
    b0.delete_keys([k0])

if __name__ == '__main__':
    mss_range_download()
