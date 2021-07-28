# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import requests
import argparse
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
def submit_form(form_details, url,proxy=None,cookie=None,parameter=False):
    """
    thay the text cua input bang value vao trong form r gui den url
    """
    targetUrl = urljoin(url, form_details["action"])
    # get the inputs
    data = {}
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
        replace_text=input('- Enter representation string ( Enter representation string in the input position where you need to insert XSS : ')
        print('\n Enter parameters value:')
        param_list=[]
        for input_dict in inputs:
            if input_dict["name"] is not None and (input_dict["type"] == "text" or input_dict["type"] == "search"):
                value= input('- '+str(input_dict['name'])+' : ')
                param_list.append(value)
                if value==replace_text:
                    data[input_dict['name']]="<script>alert('XSS')</script>"
                else:
                    data[input_dict['name']] = str(value)
        if replace_text not in param_list:
            print('FAILT: there is no representation string in the parameter list ')
            input('Press any key to try again')
            return submit_form(form_details, url,proxy,cookie,parameter)
    print(f'Scanning for {url}\n')
    if form_details["method"] == "post":
        return requests.post(targetUrl,headers=header,proxies=proxy,cookies=cookie, data=data)
    else:
        # GET request
        return requests.get(targetUrl,headers=header,proxies=proxy,cookies=cookie, params=data)
def scan_xss(url,cookie,proxy,output=None,param=False):
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
    print('[-] PROCESSING:')
    print(f"\n\t[+] Detected {len(forms)} forms on {url}.")
    # duyet qua cac form
    # if param is True:

    count=0
    for form in forms:
        details = form_details(form)
        content = submit_form(details, url,proxy=_proxy,cookie=_cookie,parameter=param).content.decode()
        if js_Text in content:
            print("\t[+] Detected form contain XSS ")
            count += 1

    print('='*50,f'\n[-] RESULT: Detect {count} form containing XSS on {url}')
if __name__ == '__main__':

    option=argparse.ArgumentParser(' XSS Scanner many option')
    option.add_argument('-u','--Url',type=str,help='Scan target')
    option.add_argument('-p','--Params',action='store_true',help='option allow enter parameters in site')
    option.add_argument('--Proxy',type=str,help='option allow send request with Proxy')
    option.add_argument('-c','--Cookie',type=str,help='option allow send request with cookie')
    option.add_argument('-o','--OutFile',type=str,help='Write result out File')
    ot = option.parse_args()

    file = ''
    if ot.OutFile is not None:
        file=ot.OutFile
    if ot.Params is True:
        scan_xss(ot.Url,cookie=ot.Cookie,proxy=ot.Proxy,param=True)
    else:
        scan_xss(ot.Url, cookie=ot.Cookie, proxy=ot.Proxy, param=False)