#!/usr/bin/env python
# -*- coding: utf-8 -*-
import base64
import random
import hmac
import time
import json
from datetime import datetime, timedelta

from flask import Flask, request, redirect, make_response

app = Flask(__name__)

users = {
    "yifeng": ["123456"]  # use a dict to store a user's username and password
}

redirect_uri = 'http://127.0.0.1:5000/client/passport'
client_id = 'client123'
users[client_id] = []
auth_code = {}    # use a dict to store authorization code
oauth_redirect_uri = []

TIME_OUT = 3600 * 2


def gen_token(data):   # generalize token

    '''
    
    :param data: dict type
    :return: base64 str
    '''

    data = data.copy()

    if "salt" not in data:
        data["salt"] = unicode(random.random()).decode("ascii")
    if "expires" not in data:
        data["expires"] = time.time() + TIME_OUT

    payload = json.dumps(data).encode("utf-8")  # dict to json str

    # generalize signature
    sig = _get_signature(payload)   # generalize 16-bit string
    return encode_token_bytes(payload + sig) # json str + signature = new token  32-bit str


# this function is to generalize authorization code which in this case is just a random number
def gen_auth_code(uri, user_id):   # when verify code, uri is needed as well
    code = random.randint(0, 10000)
    auth_code[code] = [uri, user_id]
    return code   # authorization code


def verify_token(token):  # verify token
    '''
    
    :param token: base64 str
    :return: dict type
    '''
    decode_token = decode_token_bytes(str(token))  # base64 after decode
    payload = decode_token[:-16]   # start to 16th last element (uid+random+time) json string
    sig = decode_token[-16:]       # 16th last to the end (sig)

    # generalize signature
    expected_sig = _get_signature(payload)
    if sig != expected_sig:
        return {}
    data = json.loads(payload.decode("utf-8"))   # if token is correct, json str to dict
    if data.get("expires") >= time.time():  # if token not expired
        return data
    return 0


def _get_signature(value):  # HMAC ALGORITHM
    """Calculate the HMAC signature for the given value(any string)."""
    return hmac.new('secret123456', value).digest()


def encode_token_bytes(data):
    return base64.urlsafe_b64encode(data)


def decode_token_bytes(data):
    return base64.urlsafe_b64decode(data)


# verification-server-side:
@app.route('/index', methods=['POST', 'GET'])
def index():
    # print request.headers # print acquired headers to console
    print(request.headers)
    return "Hello"


# verify user's username and password correct or not,if correct return user a token
@app.route('/login', methods=['POST', 'GET'])
def login():
    # request's header to store user's uid and pw
    uid, pw = base64.b64decode(request.headers['Authorization'].split(' ')[-1]).split(':')
    if users.get(uid)[0] == pw:
        return gen_token(dict(user=uid, pw=pw))
    else:
        return 'error'


# this function is to handle all the stuff with login verification
# it needs to check if the authorization code and uri redirection are correct or not
# if all the requirements match, then release the token
@app.route('/oauth', methods=['POST', 'GET'])
def oauth():
    # handle form login, and set Cookie meanwhile
    if request.method == 'POST' and request.form['user']:
        u = request.form['user']
        p = request.form['pw']
        if users.get(u)[0] == p and oauth_redirect_uri:
            uri = oauth_redirect_uri[0] + '?code=%s' % gen_auth_code(oauth_redirect_uri[0], u)
            expire_date = datetime.now() + timedelta(minutes=1)
            resp = make_response(redirect(uri))
            resp.set_cookie('login', '_'.join([u, p]), expires=expire_date)
            return resp
    # verify authorization code and release token
    if request.args.get('code'):
        auth_info = auth_code.get(int(request.args.get('code')))     # code = redirect_uri + client_id
        if auth_info[0] == request.args.get('redirect_uri'):
            # store client_id in auth_code of authorization code and package it in the token
            target1 = 'http://127.0.0.1:5000/test1?token=%s' %gen_token(dict(client_id=request.args.get('client_id'), user_id=auth_info[1]))
            return redirect(target1)    # gen_token(dict(client_id=request.args.get('client_id'), user_id=auth_info[1]))

    # if current login user has Cookie, skip verification, otherwise fill the form
    if request.args.get('redirect_uri'):
        oauth_redirect_uri.append(request.args.get('redirect_uri'))
        if request.cookies.get('login'):
            u, p = request.cookies.get('login').split('_')
            if users.get(u)[0] == p:
                uri = oauth_redirect_uri[0] + '?code=%s' % gen_auth_code(oauth_redirect_uri[0], u)
                return redirect(uri)
        return '''
           <form action="" method="post">
               <p><input type=text name=user>
               <p><input type=text name=pw>
               <p><input type=submit value=Login>
           </form>
               '''

    # if request.args.get('redirect_uri'):
    #     oauth_redirect_uri.append(request.args.get('redirect_uri'))
    # if request.args.get('user'):
    #     if users.get(request.args.get('user'))[0] == request.args.get('pw') and oauth_redirect_uri:  # user offers pw
    #         uri = oauth_redirect_uri[0] + '?code=%s' % gen_auth_code(oauth_redirect_uri[0])  # if pw, offer auth_code
    #         return redirect(uri)   # this redirect is to check the code see in next if
    # if request.args.get('code'):    # to check the request has auth code and earlier offered redirect_uri or not
    #     if auth_code.get(int(request.args.get('code'))) == request.args.get('redirect_uri'):
    #         return gen_token(request.args.get('client_id'))  # if no problem, give client the token
    # return 'please login'


# client-side:
# this function is to redirect all the requests sent to /client/login to http://localhost:5000/oauth
@app.route('/client/login', methods=['POST', 'GET'])
def client_login():
    uri = 'http://127.0.0.1:5000/oauth?response_type=code&client_id=%s&redirect_uri=%s' % (client_id, redirect_uri)
    return redirect(uri)


@app.route('/client/passport', methods=['POST', 'GET'])
def client_passport():
    code = request.args.get('code')
    uri = 'http://127.0.0.1:5000/oauth?grant_type=authorization_code&code=%s&redirect_uri=%s&client_id=%s' \
          % (code, redirect_uri, client_id)
    return redirect(uri)


# resource-server-side:
@app.route('/test1', methods=['POST', 'GET'])
def test():
    token = request.args.get('token')
    ret = verify_token(token)
    google = 'http://www.google.com'
    if ret:
        return redirect(google)    # json.dumps(ret)
    else:
        return 'error'


if __name__ == '__main__':
    app.run(debug=True)
