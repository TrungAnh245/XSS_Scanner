# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

def get_forms(url):
    """lay cac form trong trang"""
    content = bs(requests.get(url).content, "html.parser")
    return content.find_all("form")
def form_details(form):
    """
    trich xuat thong tin trong the form
    """
    details = {}
    #lay action cua form
    action = form.attrs.get("action").lower()
    # lay phuong thuc cua form
    method = form.attrs.get("method", "get").lower()
    # lay name va type cac the input
    inputs = []
    for inputTag in form.find_all("input"):
        inputType = inputTag.attrs.get("type", "text")
        inputName = inputTag.attrs.get("name")
        inputs.append({"type": inputType, "name": inputName})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details
def submit_form(form_details, url, value):
    """
    thay the text cua input bang value vao trong form r gui den url
    """
    targetUrl = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # thay the doan script vao text cua input
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        inputName = input.get("name")
        inputValue = input.get("value")
        if inputName!=None and inputValue!=None:
            data[inputName] = inputValue

    if form_details["method"] == "post":
        return requests.post(targetUrl, data=data)
    else:
        # GET request
        return requests.get(targetUrl, params=data)
def scan_xss(url):
    """
    Scan xss
    """
    forms = get_forms(url)
    js_Text = "<script>alert('XSS')</script>"
    vuln = False
    # duyet qua cac form
    for form in forms:
        details = form_details(form)
        content = submit_form(details, url, js_Text).content.decode()
        if js_Text in content:
            print("[+] XSS Detected on ",url)
            vuln = True
    return vuln
if __name__ == '__main__':
    print("Enter URL:")
    Url=input()
    print("Result:")
    scan_xss(Url)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
