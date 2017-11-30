#!/usr/bin/env python
# encoding: utf-8

from mssapi.s3.connection import S3Connection
from mssapi.exception import MssapiServerError
from mssapi.exception import MssapiClientError
from mssapi.compat import http_client
import hashlib
import os

MSS_HOST = 'MSS 访问域名'
MSS_ACCESS_KEY = '**************'
MSS_ACCESS_SECRET = '****************'


FILE_SEGMENT_SIZE = 5 * 1024 * 1024
template = FILE_SEGMENT_SIZE * 'b'


def mss_test_multipart_upload_prepare(filename, size):
    with open(filename, 'wb') as fp:
        offset = 0
        while offset < size:
            fp.write(template)
            offset += FILE_SEGMENT_SIZE


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


def mss_test_multipart_upload(bucket, filename):
    total_size = os.path.getsize(filename)
    with open(filename, 'rb') as fp:
        mp = bucket.initiate_multipart_upload(filename)
        part_num = 1
        part_offset = 0
        while part_offset < total_size:
            saved_part_num = part_num
            try:
                upload_size = min(total_size - part_offset, FILE_SEGMENT_SIZE)
                part_key = mp.upload_part_from_file(fp, part_num, size=upload_size)
                print u'Upload file %s part %d: %s' % (filename, part_num, part_key.name)
                part_offset += upload_size
                part_num += 1
            finally:
                if saved_part_num == part_num:
                    mp.cancel_upload()
        mp.complete_upload()
    print u'multipart upload done'


def mss_test_multipart_set_meta(bucket, key_name, new_meta, minus_meta={}):
    print u'multipart upload set meta'
    key = bucket.get_key(key_name)
    return key.set_remote_metadata(metadata_plus=new_meta,metadata_minus=minus_meta)

def mss_test_compute_md5(filename):
    hash_md5 = hashlib.md5()
    with open(filename, 'rb') as fp:
        content = fp.read(FILE_SEGMENT_SIZE)
        hash_md5.update(content)
    return hash_md5.hexdigest()


def mss_test_multipart_upload_test():
    # prepare file
    filename = "multipart-test.txt"
    filesize = 20 * 1024 * 1024 + 100
    mss_test_multipart_upload_prepare(filename, filesize)
    # init s3 connection
    conn = S3Connection(aws_access_key_id=MSS_ACCESS_KEY, aws_secret_access_key=MSS_ACCESS_SECRET, host=MSS_HOST)
    # get bucket
    b0 = mss_test_get_bucket(conn, 'example')

    # upload object with multipart
    mss_test_multipart_upload(b0, filename)

    # set metadata
    mss_test_multipart_set_meta(b0, filename, {'x-amz-meta-location': 'Beijing', 'content-type': 'text/plain'})
    key = b0.get_key(filename)
    assert key.content_type == 'text/plain'
    assert 'Beijing' == key.get_metadata('location')

    # copy object
    print 'copy object'
    b0.copy_key(key.name + '.copy', b0.name, key.name)
    cpy_key = b0.get_key(key.name + '.copy')

    # metadata check after copy
    assert cpy_key.name == key.name + '.copy'
    assert cpy_key.content_type == 'text/plain'
    assert 'Beijing' == cpy_key.get_metadata('location')

    # update metadata
    mss_test_multipart_set_meta(b0, filename + '.copy', new_meta={'x-amz-meta-location': 'Shanghai'}, minus_meta={'content-type': 'application/octet-stream'})
    cpy_key = b0.get_key(filename + '.copy')

    # check metadata
    assert cpy_key.content_type is None
    assert 'Shanghai' == cpy_key.get_metadata('location')

    # download object
    print u'------- 文件比对 ------'
    cpy_key.get_contents_to_filename(cpy_key.name)

    # compare
    assert os.path.getsize(key.name) == os.path.getsize(cpy_key.name)
    assert mss_test_compute_md5(cpy_key.name) == mss_test_compute_md5(cpy_key.name)
    print u'比对成功'


if __name__ == '__main__':
    try:
        mss_test_multipart_upload_test()
    except MssapiServerError as e:
        print "server error: %s %s" % (e.error_code, e.message)
    except MssapiClientError as e:
        print "client error: %s" % e.reason
    except http_client.HTTPException as e:
        print "http error: %s" % e
    except Exception as e:
        import traceback
        print "other error: %s-%s" % (e, traceback.format_exc())
