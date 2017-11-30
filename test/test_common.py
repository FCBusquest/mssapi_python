#!/usr/bin/env python
# encoding: utf-8


def create_bucket(conn, name):
    b = conn.lookup(name)
    if b:
        b.delete_keys([k for k in b])
        conn.delete_bucket(b.name)
    b = None
    return conn.create_bucket(name)
