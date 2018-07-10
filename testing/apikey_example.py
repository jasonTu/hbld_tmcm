'''
API Key example script.
Author: Jason Tu
Email: wood2001@126.com
'''
import time
import hashlib
import requests


G_APP_KEY = 'ca2bf41f1910a9c359370ebf87caeafd'
G_SIGN_KEY = '21be83530509abc81aa945a02bec37601cf3cc21'


def gen_signature(qparams):
    '''
    Generate signature by query string params.
    e.g.:
    /api/v1/basicinfo/?timestamp=1531019847&sign=04e9e630869012b9ca1e6d9d1ceec1ec604e95cb&app_key=ca2bf41f1910a9c359370ebf87caeafd
    sign: 04e9e630869012b9ca1e6d9d1ceec1ec604e95cb --> the client calculate signature
    app_key: ca2bf41f1910a9c359370ebf87caeafd  --> app key
    timestamp: 1531019847 --> timestamp when the request send
    Firstly need sort the query string params by the key name order,
    remove the link character like "&" and "=",
    initial the contacted string as sign key(21be83530509abc81aa945a02bec37601cf3cc21),
    then the concacted string is:
    21be83530509abc81aa945a02bec37601cf3cc21app_keyca2bf41f1910a9c359370ebf87caeafdtimestamp1531019847
    code the string with sha1 algorithm:
    '''
    keys = list(qparams.keys())
    keys.sort()
    contact_str = G_SIGN_KEY
    for key in keys:
        contact_str += key + qparams[key]
    print(contact_str)
    sign = hashlib.sha1(contact_str.encode()).hexdigest()
    return sign


def query_basicinfo():
    '''Example for get osce agent info.'''
    url = 'http://192.168.1.198:18080/api/v1/basicinfo/'
    ts = int(time.time())
    query_params = {
        'timestamp': str(ts),
        'app_key': G_APP_KEY,
    }
    sign = gen_signature(query_params)
    query_params['sign'] = sign
    resp = requests.get(url, params=query_params)
    print(resp.status_code)
    print(resp.json())


def query_scan_detail():
    '''Example for get osce scan detail info.'''
    url = 'http://192.168.1.198:18080/api/v1/scandetail/'
    ts = int(time.time())
    query_params = {
        'timestamp': str(ts),
        'app_key': G_APP_KEY,
        'agent': '192.168.1.55',
        'begin': '2018-07-04',
        'end': '2018-07-10'
    }
    sign = gen_signature(query_params)
    query_params['sign'] = sign
    resp = requests.get(url, params=query_params)
    print(resp.status_code)
    print(resp.json())


if __name__ == '__main__':
    query_scan_detail()
    query_basicinfo()
