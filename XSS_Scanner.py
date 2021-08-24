# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
#!/usr/bin/env python3
import requests
import argparse
import re
import urllib.parse

from http.cookies import SimpleCookie
# from bs4 import BeautifulSoup as bs
# from urllib.parse import urljoin


header={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Safari/537.36 OPR/77.0.4054.277'}
def scan_xss_with_get_method(url,params,cookie,proxy):
    _proxy = {}
    # phan tich proxy tho thanh dict
    if proxy is not None:
        _proxy[proxy[:proxy.find(':')]] = proxy
    else:
        _proxy = None
    print('=' * 50)
    print('[-] PAYLOAD:')
    print(f'\t[+] URL: {url}')
    print('\t[+] Method: GET')
    print(f'\t[+] Cookie: {cookie}')
    print(f'\t[+] Proxy: {proxy}')
    print(f'\t[+] Parameter: {params}')
    print('=' * 50)
    print('[-] PROCESSING')
    script_text_list=re.findall(r'script.*>.*<.*/.*script',str(params).lower())
    #phan tich chuoi param thanh dict
    _params = urllib.parse.parse_qs(str(params))
    for key,value in _params.items():
        _params[key]=value[0]

    for i in range(0,len(script_text_list)):
        script_text_list[i]=re.sub(r'script.*>','',script_text_list[i])
        script_text_list[i] = re.sub(r'<.*/.*script', '', script_text_list[i])
        script_text_list[i]=script_text_list[i]
    #phan tich chuoi cookie thanh dict
    _cookie = {}
    if cookie is not None:
        cookie = str(cookie)
        cookie = cookie[cookie.find(':') + 1:].strip()
        partial = cookie.split(';')
        for temp in partial:
            key_value_list = temp.split('=')
            _cookie[key_value_list[0]] = key_value_list[1]
        # them vao danh sach XSS tu gia tri cua cookie neu co
        for value in _cookie.values():
            temp = value.lower()
            if re.search(r'script.*>.*<.*/.*script', temp) is not None:
                temp = re.findall(r'script.*>.*<.*/.*script', temp)[0]
                temp = re.sub(r'script.*>', '', temp)
                temp = re.sub(r'<.*/.*script', '', temp)
                script_text_list.append(temp)
    else:
        _cookie = None
    url=url+'?'+params
    content=requests.get(url,params=_params,headers=header,proxies=_proxy,cookies=_cookie).content.decode().lower()
    count=0
    for script in script_text_list:
        if re.search(r'<\s*script\s*>'+re.escape(script)+ r'<\s*/\s*script\s*>',content) is not None:
            print("\t[+] Detected XSS ")
            count += 1
    print('=' * 50, f'\n[-] RESULT: Detect {count} parameter contain XSS on {url}')
def scan_xss_with_post_method(url,params,cookie,proxy):
    _proxy = {}
    # phan tich proxy tho thanh dict
    if proxy is not None:
        _proxy[proxy[:proxy.find(':')]] = proxy
    else:
        _proxy = None
    #phan tich chuoi param thanh dict
    _data=urllib.parse.parse_qs(str(params))

    #tim doan xss trong cac tham so
    script_text_list=[]
    for key,value in _data.items():
        _data[key]=value[0]
        temp=value[0].lower()
        if re.search(r'script.*>.*<.*/.*script',temp) is not None:
            temp=re.findall(r'script.*>.*<.*/.*script',temp)[0]
            temp=re.sub(r'script.*>','',temp)
            temp=re.sub(r'<.*/.*script','',temp)
            script_text_list.append(temp)

    # phan tich chuoi cookie thanh dict
    _cookie = {}
    if cookie is not None:
        cookie = str(cookie)
        cookie = cookie[cookie.find(':') + 1:].strip()
        partial = cookie.split(';')
        for temp in partial:
            key_value_list = temp.split('=')
            _cookie[key_value_list[0]] = key_value_list[1]
        # them vao danh sach XSS tu gia tri cua cookie neu co
        for value in _cookie.values():
            temp = value.lower()
            if re.search(r'script.*>.*<.*/.*script', temp) is not None:
                temp = re.findall(r'script.*>.*<.*/.*script', temp)[0]
                temp = re.sub(r'script.*>', '', temp)
                temp = re.sub(r'<.*/.*script', '', temp)
                script_text_list.append(temp)
    else:
        _cookie = None

    print('=' * 50)
    print('[-] PAYLOAD:')
    print(f'\t[+] URL: {url}')
    print('\t[+] Method: POST')
    print(f'\t[+] Cookie: {cookie}')
    print(f'\t[+] Proxy: {proxy}')
    print(f'\t[+] Parameter: {params}')
    print('=' * 50)
    print('[-] PROCESSING')

    #---------------------------------------------------------------
    content=requests.post(url,headers=header,data=_data,cookies=_cookie,proxies=_proxy).content.decode().lower()
    count = 0
    for script in script_text_list:
        match=re.findall(r'<\s*script\s*>'+re.escape(script)+ r'<\s*/\s*script\s*>', content)
        if len(match) !=0:
            print("\t[+] Detected XSS ")
            count += 1
    print('=' * 50, f'\n[-] RESULT: Detect {count} parameter contain XSS on {url}')
def scan_xss_with_cookie(url,cookie):
    _cookie = {}
    # phan tich chuoi cookie  thanh dict
    cookie=str(cookie)
    cookie=cookie[cookie.find(':')+1:].strip()
    partial=cookie.split(';')
    for temp in partial:
        key_value_list=temp.split('=')
        _cookie[key_value_list[0]]=key_value_list[1]

    #tim xss trong cac tham so cua cookie
    script_text_list = []
    for value in _cookie.values():
        temp = value.lower()
        if re.search(r'script.*>.*<.*/.*script', temp) is not None:
            temp = re.findall(r'script.*>.*<.*/.*script', temp)[0]
            temp = re.sub(r'script.*>', '', temp)
            temp = re.sub(r'<.*/.*script', '', temp)
            script_text_list.append(temp)

    print('=' * 50)
    print('[-] PAYLOAD:')
    print(f'\t[+] Cookie: {cookie}')
    print('=' * 50)
    print('[-] PROCESSING')
    content = requests.get(url,headers=header, cookies=_cookie).content.decode().lower()
    count = 0

    for script in script_text_list:
        match = re.findall(r'<\s*script\s*>' + re.escape(script) + r'<\s*/\s*script\s*>', content)
        if len(match) != 0:
            print("\t[+] Detected XSS ")
            count += 1
    print('=' * 50, f'\n[-] RESULT: Detect {count} parameter contain XSS on {url}')
if __name__ == '__main__':

    option=argparse.ArgumentParser(' XSS Scanner many option')
    option.add_argument('-u','--Url',type=str,help='Scan target')
    option.add_argument('-g', '--GET', type=str, help='Scan with GET method')
    option.add_argument('-p', '--POST',type=str, help='Scan with POST method')
    # option.add_argument('-i','--Input',action='store_true',help='option allow enter parameters in site')
    option.add_argument('--Proxy',type=str,help='option allow send request with Proxy')
    option.add_argument('-c','--Cookie',type=str,help='option allow send request with cookie')
    ot = option.parse_args()


    if ot.GET is not None:
        scan_xss_with_get_method(ot.Url,params=ot.GET,cookie=ot.Cookie,proxy=ot.Proxy)
    elif ot.POST is not None:
        scan_xss_with_post_method(ot.Url,params=ot.POST,cookie=ot.Cookie,proxy=ot.Proxy)
    elif ot.Cookie is not None:
        scan_xss_with_cookie(ot.Url,ot.Cookie)
