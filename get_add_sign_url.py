# -*- coding: utf8 -*-

import os,sys
import json
from urllib import request
from urllib import parse
import urllib
import base64
import hmac
import hashlib
import time
import datetime
import random
from config.setting import *

utc_iso = (datetime.datetime.now() - datetime.timedelta(hours=8)).isoformat().split(".")[0] + 'Z'
yesterday_utc_iso = (datetime.datetime.now() - datetime.timedelta(hours=8) - datetime.timedelta(days=1)).isoformat().split(".")[0] + 'Z'
yesterday_iso = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat().split(".")[0] + 'Z'
now_iso = (datetime.datetime.now()).isoformat().split(".")[0] + 'Z'
time_stamp = str(int(time.time())) + '0000'
signature_nonce = str(int(time.time()) + random.randint(50000,100000))

argv_dict = {
    'Format':'JSON',
    'Version':'2019-01-01',
    'AccessKeyId':access_key_id,
    'SignatureMethod':'HMAC-SHA1',
    'SignatureVersion':"1.0",
    'SignatureNonce':signature_nonce,
    'Timestamp':now_iso,
    'Action':'DescribeProjectMeta',
}

#转化为排序后的参数列表
def get_sort_argv_list(dict):

    sort_argv_list = sorted(argv_dict.items(),key=lambda x: x[0])
    return sort_argv_list

#进行url编码
def percent_encode(string):

    res = parse.quote(string.encode('utf8').decode(sys.stdin.encoding).encode('utf8'),'')
    res = res.replace('+','%20')
    res = res.replace('*','%2A')
    res = res.replace('%7E','~')
    return res

#获取需要加密的字符串
def get_string_to_sign():

    sort_argv_list = get_sort_argv_list(argv_dict)

    #按照规定拼出需要加密的字符串
    std_string = ''
    for k,v in sort_argv_list:
        std_string += '&' + percent_encode(k) + percent_encode('=') + percent_encode(v)

    string_to_sign = 'GET&%2F&' + std_string[1:]
    print (string_to_sign)
    return string_to_sign

def get_signature():

    #现将str转换为bytes
    string_to_sign = get_string_to_sign()
    new_access_key_secret = access_key_secret + "&"
    access_key_secret_bytes = bytes(new_access_key_secret,"utf8")
    string_to_sign_bytes = bytes(string_to_sign,"utf8")

    #计算hmac值
    hmac_string = hmac.new(access_key_secret_bytes,string_to_sign_bytes,hashlib.sha1)

    #base64计算签名值
    signature = base64.encodebytes(hmac_string.digest()).strip()

    argv_dict['Signature'] = signature

    return argv_dict


def get_signed_url():

    url = "http://metrics.cn-beijing.aliyuncs.com/?"

    new_argv_dict = get_signature()
    argvs = parse.urlencode(new_argv_dict)


    url = url + argvs 

    print(url)

get_signed_url()

