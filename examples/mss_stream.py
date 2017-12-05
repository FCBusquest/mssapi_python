#!/usr/bin/env python
# encoding: utf-8

import hashlib
import os
from mssapi.exception import MssapiServerError
from mssapi.s3.connection import S3Connection

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


def mss_test_stream_prepare(filename, size):
    with open(filename, 'wb') as fp:
        offset = 0
        while offset < size:
            part_size = min(1024*1024, size - offset)
            fp.write(part_size * 'a')
            offset += part_size


def mss_test_file_md5(fp, size):
    hash_md5 = hashlib.md5()
    offset = 0
    while offset < size:
        part_size = min(1024*1024, size - offset)
        hash_md5.update(fp.read(part_size))
        offset += part_size
    return hash_md5.hexdigest()


def mss_test_filename_md5(filename):
    import os
    size = os.path.getsize(filename)
    with open(filename, 'rb') as fp:
        return mss_test_file_md5(fp, size)


def mss_stream_upload_download():
    filename = 'stream_test.origin'
    conn = S3Connection(aws_access_key_id=MSS_ACCESS_KEY, aws_secret_access_key=MSS_ACCESS_SECRET, host=MSS_HOST)
    b0 = mss_test_get_bucket(conn, 'example')

    # prepare file
    print 'prepare origin file'
    mss_test_stream_prepare(filename, 11*1024*1024)
    md5_origin = mss_test_filename_md5(filename)

    # upload file
    print 'upload from stream..'
    k0 = b0.new_key('stream_test.mss')
    with open(filename, 'rb') as fp:
        k0.set_contents_from_stream(fp)

    # check md5
    k0 = b0.get_key('stream_test.mss')
    assert k0.etag.strip('"') == md5_origin

    print 'stream reading..'
    hash_md5 = hashlib.md5()
    try:
        for bytes in k0:
            hash_md5.update(bytes)
    except:
        k0.close()
        raise
    assert md5_origin == hash_md5.hexdigest()

    print 'stream reading with Key read'
    hash_md5 = hashlib.md5()
    try:
        offset = 0
        while offset < k0.size:
            part_size = min(1000, k0.size - offset)
            hash_md5.update(k0.read(part_size))
            offset += part_size
    except:
        k0.close()
        raise

    b0.delete_keys([k0])

    os.remove(filename)


if __name__ == '__main__':
    mss_stream_upload_download()
