#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import random
import time
from flask import Flask,request

app = Flask(__name__)

users = {
    "yifeng" : ["123456"] #use a dict to store a user's username and password
}

def gen_token(uid): #generalize token
    #generalize the token using username,random number and timestamp+7200s, linked with ':'
    token = base64.b64encode(':'.join([str(uid),str(random.random()),str(time.time() + 7200)]))
    users[uid].append(token) # password + token
    return token

def verify_token(token): #verify token
    _token = base64.b64decode(token)        #decode token by base64
    if not users.get(_token.split(':')[0])[-1] == token: #user.get() get the key of password + token,[-1] responds to token
        return -1
    if float(_token.split(':')[-1]) >= time.time():  #time has not expired
        return 1
    else:
        return 0

@app.route('/index',methods=['POST','GET']) #路由地址
def index():
    # print request.headers #用来将获取到的请求头打印到console
    print(request.headers)
    return "Hello"

@app.route('/login',methods=['POST','GET']) #verify user's username and password correct or not,if correct return user a token
def login():
    #request's header to store user's uid and pw
    uid,pw = base64.b64decode(request.headers['Authorization'].split(' ')[-1]).split(':').encode()
    if users.get(uid)[0] == pw:
        return gen_token(uid)
    else:
        return 'error'

@app.route('/test',methods=['POST','GET'])
def test():
    token = request.args.get('token')
    if verify_token(token) == 1:
        return 'data'
    else:
        return 'error'


if __name__ == '__main__':
    app.run()
