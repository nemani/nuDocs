import requests 
import urllib.parse

api_key = '52f33b0158c319fd8afe53610f55289965993970164ea71212fe63'


def set_value(key, value):
    key = urllib.parse.quote(key)
    url = f"https://meeiot.org/put/{api_key}/{key}"
    x = requests.post(url, json=value, verify=False)
    res = x.text
    if res[0] == "0":
        return True
    return False
    
    


def get_value(key):
    key = urllib.parse.quote(key)
    url = f"https://meeiot.org/get/{api_key}/{key}"
    x = requests.get(url, verify=False)
    try:
        return x.json()
    except Exception as e:
        return None
