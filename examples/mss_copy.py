#!/usr/bin/env python
# encoding: utf-8

from mssapi.s3.connection import S3Connection
from mssapi.exception import MssapiServerError
from mssapi.exception import MssapiClientError
from mssapi.compat import http_client
from mssapi.compat import encodebytes

from hashlib import md5
import os

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


def _get_data_md5(string_data):
    """
    See compute_hash in mssapi.utils
    """
    hash_obj = md5()
    if not isinstance(string_data, bytes):
        string_data = string_data.encode('utf-8')
    hash_obj.update(string_data)

    hex_digest = hash_obj.hexdigest()
    base64_digest = encodebytes(hash_obj.digest()).decode('utf-8')
    return hex_digest, base64_digest


def mss_test_copy_example():
    data = 'AAAAAAA'
    conn = S3Connection(aws_access_key_id=MSS_ACCESS_KEY, aws_secret_access_key=MSS_ACCESS_SECRET, host=MSS_HOST)
    # get bucket
    b0 = mss_test_get_bucket(conn, 'example')

    # caculate md5
    hex_digest, base64_digest = _get_data_md5(data)

    # upload
    key = b0.new_key('src_file')
    key.set_contents_from_string(data, md5=(hex_digest, base64_digest), headers={'content-type': 'text/plain'})
    print '[DONE] create test file'

    # set meta
    key.set_remote_metadata(metadata_plus={'x-amz-meta-location': 'Beijing', 'content-type': 'application/octet-stream'}, metadata_minus={})
    print '[DONE] set meta'

    # head object
    key = b0.get_key('src_file')

    # copy file in the same bucket
    # b0.copy_key('dst_file', b0.name, 'src_file') is also ok
    key.copy(b0.name, 'dst_file')
    cpy_key = b0.get_key('dst_file')
    print '[DONE] copy object in the same bucket'

    # check
    key.copy(b0.name, 'dst_file')
    try:
        cpy_data = cpy_key.get_contents_as_string()
    except:
        key.close()
        raise
    assert data == cpy_data
    assert key.content_type == cpy_key.content_type
    assert key.content_type == 'application/octet-stream'
    assert key.get_metadata('location') == 'Beijing'
    assert cpy_key.get_metadata('location') == 'Beijing'
    print '[DONE] check new object'

    # copy file in another bucket
    # new_b0.copy_key('dst_file', b0.name, 'src_file') is also ok
    new_b0 = mss_test_get_bucket(conn, 'backup')
    key.copy(new_b0.name, 'dst_file')
    cpy_key = new_b0.get_key('dst_file')
    print '[DONE] copy object another bucket'

    # check
    try:
        cpy_data = cpy_key.get_contents_as_string()
    except:
        key.close()
        raise
    assert data == cpy_data
    assert key.content_type == cpy_key.content_type
    assert key.content_type == 'application/octet-stream'
    assert key.get_metadata('location') == 'Beijing'
    assert cpy_key.get_metadata('location') == 'Beijing'
    print '[DONE] check new object'

    b0.delete_keys([key, 'dst_file'])
    new_b0.delete_key('dst_file')


if __name__ == '__main__':
    try:
        mss_test_copy_example()
    except MssapiServerError as e:
        print "server error: %s %s" % (e.error_code, e.message)
    except MssapiClientError as e:
        print "client error: %s" % e.reason
    except http_client.HTTPException as e:
        print "http error: %s" % e
    except Exception as e:
        import traceback
        print "other error: %s-%s" % (e, traceback.format_exc())
