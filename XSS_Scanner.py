# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
#!/usr/bin/env python3
import requests
import argparse
import re
import urllib.parse
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from http.cookies import SimpleCookie

header={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Safari/537.36 OPR/77.0.4054.277'}
def get_forms(url):
    """lay cac form trong trang"""
    content = bs(requests.get(url,headers=header).content, "html.parser")
    return content.find_all("form")
def form_details(form):
    """
    trich xuat thong tin trong the form
    """

    details = {}
    #lay action cua form
    action = form.attrs['action'].lower()
    # lay phuong thuc cua form
    method = form.attrs.get('method','get').lower()
    details["action"] = action
    details["method"] = method
    # lay name va type cac the input
    inputs = []
    for inputTag in form.find_all("input"):
        inputType = inputTag.attrs.get("type", "text")  #lay value trong dict bang key, neu k ton tai key thi tra ve text
        inputName = inputTag.attrs.get("name")
        inputs.append({"type": inputType, "name": inputName})
    details["inputs"] = inputs
    return details
def submit_form(form_details, url,script_list=None,proxy=None,cookie=None,parameter=False):
    """
    thay the text cua input bang value vao trong form r gui den url
    """
    targetUrl = urljoin(url, form_details["action"])
    # get the inputs
    data = {}
    script_param_list=[]
    inputs = form_details["inputs"]
    if  parameter is False:
        for input_dict in inputs:
            # thay the doan script vao text cua input
            if input_dict["type"] == "text" or input_dict["type"] == "search":
                input_dict["value"] = "<script>alert('XSS')</script>"
            inputName = input_dict['name']
            inputValue = input_dict.get("value")
            if inputName!=None and inputValue!=None:
                data[inputName] = inputValue
    else:
        # replace_text=input('- Enter representation string ( Enter representation string in the input position where you need to insert XSS : ')
        print('\n Enter parameters value:')
        for input_dict in inputs:
            if input_dict["name"] is not None and (input_dict["type"] == "text" or input_dict["type"] == "search"):
                value= input('- '+str(input_dict['name'])+' : ')
                data[input_dict['name']] = str(value)
                if 'script' in value.lower():
                    temp_list=re.findall(r'script.*>.*<.*/.*script',value.lower())
                    temp_str=re.sub(r'script.*>','',temp_list[0])
                    temp_str = re.sub(r'<.*/.*script', '', temp_str)
                    script_list.append(temp_str)
    print(f'Scanning for {url}\n')
    if form_details["method"] == "post":
        return requests.post(targetUrl,headers=header,proxies=proxy,cookies=cookie, data=data)
    else:
        # GET request
        return requests.get(targetUrl,headers=header,proxies=proxy,cookies=cookie, params=data)
def scan_xss(url,cookie,proxy,script_param_list=None,output=None,param=False):
    """
    Scan xss
    """
    _cookie={}
    _proxy={}
    # phan tich cookie tho thanh dict
    if cookie is not None:
        cookieSimple = SimpleCookie()
        cookieSimple.load(cookie)
        for key,vl in cookieSimple.items():
            _cookie[key]=vl.value
    else:
        _cookie=None
    # phan tich proxy tho thanh dict
    if proxy is not None:
        _proxy[proxy[:proxy.find(':')]] = proxy
    else:
        _proxy = None
    print('='*50)
    print('[-] PAYLOAD:')
    print(f'\t[+] Cookie: {cookie}')
    print(f'\t[+] Proxy: {proxy}')
    print('=' * 50)
    forms = get_forms(url)
    js_Text = "<script>alert('XSS')</script>"
    print('[-] PROCESSING')
    print(f"\n\t[+] Detected {len(forms)} forms on {url}.")
    # duyet qua cac form
    count = 0
    # if param is True:
    if param is True:
        for form in forms:
            details = form_details(form)
            content = submit_form(details, url,script_list=script_param_list,proxy=_proxy,cookie=_cookie,parameter=param).content.decode().lower()
            for script in script_param_list:
                if re.search(r'<\s*script\s*>'+re.escape(script)+ r'<\s*/\s*script\s*>', content) is not None:
                    print("\t[+] Detected form contain XSS ")
                    count+=1
                    break
    else:
        for form in forms:
            details = form_details(form)
            content = submit_form(details, url,proxy=_proxy,cookie=_cookie,parameter=param).content.decode()
            if js_Text in content:
                print("\t[+] Detected form contain XSS ")
                count += 1

    print('='*50,f'\n[-] RESULT: Detect {count} form containing XSS on {url}')
def scan_xss_with_get_method(url,cookie,proxy):
    _cookie = {}
    _proxy = {}
    # phan tich cookie tho thanh dict
    if cookie is not None:
        cookieSimple = SimpleCookie()
        cookieSimple.load(cookie)
        for key, vl in cookieSimple.items():
            _cookie[key] = vl.value
    else:
        _cookie = None
    # phan tich proxy tho thanh dict
    if proxy is not None:
        _proxy[proxy[:proxy.find(':')]] = proxy
    else:
        _proxy = None
    print('=' * 50)
    print('[-] PAYLOAD:')
    print('\t[+] Method: GET')
    print(f'\t[+] Cookie: {cookie}')
    print(f'\t[+] Proxy: {proxy}')
    print('=' * 50)
    print('[-] PROCESSING')
    script_text_list=re.findall(r'script.*>.*<.*/.*script',str(url).lower())
    for i in range(0,len(script_text_list)):
        script_text_list[i]=re.sub(r'script.*>','',script_text_list[i])
        script_text_list[i] = re.sub(r'<.*/.*script', '', script_text_list[i])
        script_text_list[i]=script_text_list[i]
    content=requests.get(url,proxies=_proxy,cookies=_cookie).content.decode().lower()
    count=0
    for script in script_text_list:
        if re.search(r'<\s*script\s*>'+re.escape(script)+ r'<\s*/\s*script\s*>',content) is not None:
            print("\t[+] Detected XSS ")
            count += 1
    print('=' * 50, f'\n[-] RESULT: Detect {count} parameter contain XSS on {url}')
def scan_xss_with_post_method(url,params,cookie,proxy):
    _cookie = {}
    _proxy = {}
    # phan tich cookie tho thanh dict
    if cookie is not None:
        cookieSimple = SimpleCookie()
        cookieSimple.load(cookie)
        for key, vl in cookieSimple.items():
            _cookie[key] = vl.value
    else:
        _cookie = None
    # phan tich proxy tho thanh dict
    if proxy is not None:
        _proxy[proxy[:proxy.find(':')]] = proxy
    else:
        _proxy = None
    #phan tich chuoi param thanh dict
    _data=urllib.parse.parse_qs(str(params))

    #tim doan xss trong cac tham so
    script_text_list=[]
    for value in _data.values():
        temp=value[0].lower()
        if re.search(r'script.*>.*<.*/.*script',temp) is not None:
            temp=re.findall(r'script.*>.*<.*/.*script',temp)[0]
            temp=re.sub(r'script.*>','',temp)
            temp=re.sub(r'<.*/.*script','',temp)
            script_text_list.append(temp)
    print('=' * 50)
    print('[-] PAYLOAD:')
    print('\t[+] Method: POST')
    print(f'\t[+] Cookie: {cookie}')
    print(f'\t[+] Proxy: {proxy}')
    print(f'\t[+] Parameter: {params}')
    print('=' * 50)
    print('[-] PROCESSING')
    content=requests.post(url,data=_data,cookies=_cookie,proxies=_proxy).content.decode().lower()
    count = 0
    for script in script_text_list:
        match=re.findall(r'<\s*script\s*>'+re.escape(script)+ r'<\s*/\s*script\s*>', content)
        if len(match) !=0:
            print("\t[+] Detected XSS ")
            count += 1
    print('=' * 50, f'\n[-] RESULT: Detect {count} parameter contain XSS on {url}')
def scan_xss_with_cookie(url,cookie):
    _cookie = {}
    # phan tich cookie thoo thanh dict
    partial=str(cookie).split(';')
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
    print(f'\t[+] {cookie}')
    print('=' * 50)
    print('[-] PROCESSING')
    content = requests.get(url, cookies=_cookie).content.decode().lower()
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
    option.add_argument('-g', '--GET', action='store_true', help='Scan with GET method')
    option.add_argument('-p', '--POST',type=str, help='Scan with POST method')
    option.add_argument('-i','--Input',action='store_true',help='option allow enter parameters in site')
    option.add_argument('--Proxy',type=str,help='option allow send request with Proxy')
    option.add_argument('-c','--Cookie',type=str,help='option allow send request with cookie')

    ot = option.parse_args()


    if ot.GET is True:
        scan_xss_with_get_method(ot.Url,cookie=ot.Cookie,proxy=ot.Proxy)
    elif ot.POST is not None:
        scan_xss_with_post_method(ot.Url,params=ot.POST,cookie=ot.Cookie,proxy=ot.Proxy)
    elif ot.Cookie is not None:
        scan_xss_with_cookie(ot.Url,ot.Cookie)
    else:
        if ot.Input is True:
            script_param_list = []
            scan_xss(ot.Url,script_param_list=script_param_list,cookie=ot.Cookie,proxy=ot.Proxy,param=True)
        else:
            scan_xss(ot.Url, cookie=ot.Cookie, proxy=ot.Proxy, param=False)