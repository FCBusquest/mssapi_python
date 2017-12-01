import mssapi
from mssapi.s3.connection import S3Connection
from mssapi.s3.key import Key

from test_common import create_bucket
import test_util

conn = test_util.get_conn()

b0 = create_bucket(conn, 'tmpbucket0')
b1 = create_bucket(conn, 'tmpbucket1')

bs = conn.get_all_buckets()
for b in bs:
    print b.name

b1 = conn.get_bucket('tmpbucket1')

conn.delete_bucket(b1)

conn.head_bucket('tmpbucket0')

'tmpbucket0' in conn

keys = b0.get_all_keys()
for k in keys:
    print k.name

bucket = conn.get_bucket('tmpbucket0')

k0 = bucket.new_key('key0')
k0.set_contents_from_string('hello key0')

k1 = Key(bucket, 'key1')
k1.set_contents_from_filename('./tmp/file_w1')

k0 = bucket.get_key('key0')
cont =  k0.get_contents_as_string()
print cont

k1 = Key(bucket, 'key1')
k1.get_contents_to_filename('./tmp/file_r1')

bucket.delete_key('key0')

bucket.lookup('key0')

print k1.generate_url(expires_in = 300)

mp = bucket.initiate_multipart_upload('tmpmultipartkey')

#you need to create tmp folder, and chunkfile 0, 1, 2
chunk_path = './tmp/'
chunk_num=3
for i in xrange(0, chunk_num):
    fp = open(chunk_path + str(i), 'r' )
    mp.upload_part_from_file(fp, part_num=i + 1)

mp.complete_upload()
