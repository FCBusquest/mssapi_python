#!/usr/bin/env python
# encoding: utf-8

from mssapi.s3.connection import S3Connection
from mssapi.s3.key import Key
from mssapi.s3.prefix import Prefix
from mssapi.exception import MssapiServerError
from mssapi.exception import MssapiClientError
from mssapi.compat import http_client

from hashlib import md5


MSS_HOST = 'MSS 访问域名'
MSS_ACCESS_KEY = '**************'
MSS_ACCESS_SECRET = '****************'


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


def mss_test_upload_object_file(bucket, name, filename):
    with open(filename, 'wb') as f:
        f.write("Welcome, upload data to MSS\n")
    key = bucket.new_key(name)
    key.set_contents_from_filename(filename, headers={'Content-Type': 'text/plain'})
    key = bucket.get_key(name)
    assert key.content_type == 'text/plain'
    key.set_remote_metadata(metadata_plus={'x-amz-meta-location': 'Beijing'}, metadata_minus={'content-type': 'text/plain'})
    key = bucket.get_key(name)
    print key.size, key.content_type
    assert key.content_type is None and key.get_metadata('location') == 'Beijing'


def mss_test_upload_object_data(bucket, name, data):
    key = bucket.new_key(name)
    key.set_contents_from_string(data)


def _mss_list_dir(bucket, prefix):
    keys = []
    sub_dirs = []
    iter = bucket.list(prefix=prefix, delimiter='/')
    for key in iter:
        if isinstance(key, Key):
            keys.append(key)
        elif isinstance(key, Prefix):
            sub_dirs.append(key.name)
        else:
            raise TypeError("%s type: %s" % (key, type(key)))
    return (keys, sub_dirs)


def _mss_list_dir_recurse(bucket, prefix):
    sub_dirs = [prefix]
    all_keys = []
    while len(sub_dirs) > 0:
        new_sub_dirs = []
        for sub_dir in sub_dirs:
            keys, sub_dirs_ = _mss_list_dir(bucket, sub_dir)
            new_sub_dirs.extend(sub_dirs_)
            all_keys.extend(keys)
        sub_dirs = new_sub_dirs
    return all_keys


def mss_test_list_objects(bucket):
    print u'-------- 列举所有对象 ----------'
    for key in bucket:
        print "%s: %s" % (key.name, key.etag)

    print u'-------- 列举test2目录下的对象，不包含子目录下的对象 ----------'
    keys, sub_dirs = _mss_list_dir(bucket, 'test2/')
    for key in keys:
        print "%s: %s" % (key.name, key.etag)

    print u'--------- 列举test2目录下的所有对象，包含子目录下的对象 -------'
    keys = _mss_list_dir_recurse(bucket, 'test2/')
    for key in keys:
        print "%s: %s" % (key.name, key.etag)

    print u'--------- 列举所有对象(模拟目录遍历) -------'
    keys = _mss_list_dir_recurse(bucket, '')
    for key in keys:
        print "%s: %s %s %s" % (key.name, key.etag, key.last_modified, key.size)


def mss_test_download_object(bucket, key_name):
    print u'------ 下载指定对象 ------'
    key = bucket.get_key(key_name)
    data = key.get_contents_as_string(encoding='utf-8')
    data_md5 = md5(data)
    if key.etag == '"%s"' % data_md5.hexdigest():
        valid_str = 'match'
    else:
        valid_str = 'dismatch: %s<>"%s"' % (key.etag, data_md5.hexdigest())
    print "%s: %s  %s" % (key.name, data, valid_str)


def mss_test_delete_object(bucket, key_name):
    print u'-------- 删除对象 ---------'
    bucket.delete_key(key_name)
    print u'%s 删除成功' % key_name


def mss_test_delete_objects(bucket, keys=[]):
    print u'--------- 批量删除对象 ---------'
    result = bucket.delete_keys(keys, quiet=False)
    for item in result.deleted:
        print u'%s 删除成功' % item.key
    for item in result.errors:
        print u'%s 删除失败[%s %s]' % (item.key, item.code, item.message)


def mss_test_basic_example():
    conn = S3Connection(aws_access_key_id=MSS_ACCESS_KEY, aws_secret_access_key=MSS_ACCESS_SECRET, host=MSS_HOST)
    # get bucket
    b0 = mss_test_get_bucket(conn, 'example')

    # upload objects
    mss_test_upload_object_file(b0, 'test0', 'test_file')
    mss_test_upload_object_data(b0, 'test1', u'欢迎使用MSS')
    mss_test_upload_object_data(b0, 'test2', '')
    mss_test_upload_object_data(b0, 'test2/subtest0', '')
    mss_test_upload_object_data(b0, 'test2/subtest1', '')
    mss_test_upload_object_data(b0, 'test2/subtest0/00', 'AAAAAAA')
    mss_test_upload_object_data(b0, 'test2/subtest1/00', 'aaaaaaa')
    mss_test_upload_object_data(b0, 'test2/subtest1/01', 'bbbbbbb')
    mss_test_upload_object_data(b0, 'test3/subtest0', '')
    mss_test_upload_object_data(b0, 'test3/subtest1/00', '1111111')

    # list objects
    mss_test_list_objects(b0)

    # download object
    mss_test_download_object(b0, 'test3/subtest1/00')

    # delete object
    mss_test_delete_object(b0, 'test1')

    # delete multiple objects
    mss_test_delete_objects(b0, ['test3/subtest0', 'test3/subtest1/00', b0.get_key('test0')])

    print u'------------ 剩余对象 ---------------'
    for key in b0:
        print key.name

    # delete all
    mss_test_delete_objects(b0, [key for key in b0])

    assert(0 == len([key for ken in b0]))


if __name__ == '__main__':
    try:
        mss_test_basic_example()
    except MssapiServerError as e:
        print "server error: %s %s" % (e.error_code, e.message)
    except MssapiClientError as e:
        print "client error: %s" % e.reason
    except http_client.HTTPException as e:
        print "http error: %s" % e
    except Exception as e:
        import traceback
        print "other error: %s-%s" % (e, traceback.format_exc())
