import pickle
class ScanSettings:
    def __init__(self, url, method, headers, cookies, requestbody:str, scanname):
        self.url = url
        self.method = method
        self.headers = headers
        self.cookies = cookies
        self.rbody = requestbody
        self.scanname = scanname

    def __getstate__(self):
        return {
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'cookies': self.cookies,
            'rbody': self.rbody,
            'scanname': self.scanname
        }

    def __setstate__(self, state):
        self.url = state['url']
        self.method = state['method']
        self.headers = state['headers']
        self.cookies = state['cookies']
        self.rbody = state['rbody']
        self.scanname = state['scanname']

