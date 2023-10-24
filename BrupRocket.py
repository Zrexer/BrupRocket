#!/usr/bin/env python3 

"""
BrupRocket
~~~~~~~~~~~

Web Application Cracker

Use it: 

```
from BrupRocket import BrupRocket
```
"""

import hashlib 
import requests 
import sys
import random
import socket

class Help:
    def usage():
        return """python3 BrupRocket.py [-h / --help]: get help
[-v / --version]: get version
[--get #<url> [--header: set headers => --header Content-Type:application/json : for set two header, call --header twice][--json: get json][--status: get status code][--body: get source of page]]
[--post #<url> [--header: set headers => --header Content-Type:application/json : for set two header, call --header twice][--json: get json][--status: get status code][--body: get source of page]]
[--hash #<text> [--type: set type of encrypt => optial ===> --hash Hello_world ' or ' --hash Hello_world --type sha256]]: ['sha1', 'sha256', 'sha224', 'sha512', 'sha384', 'sha3_256', 'sha3_224', 'sha3_512', 'sha3_384']
[--lolip]: get local ip of system
[--getip #<domain name>]: get ip server of domain
"""

class BrupRocket:
    def __init__(self, url : str = None, domain : str = None) -> None:
        self.url = url
        self.domain = domain
        self.hashlib = hashlib
        self.argv = sys.argv
        self.pool = requests
        self.rand = random
        self.socket = socket
        self.hashlist = ['sha1', 'sha256', 'sha224', 'sha512', 'sha384', 'sha3_256', 'sha3_224', 'sha3_512', 'sha3_384']
        self.note = "[*]"
        self.true = "[+]"
        self.false = "[-]"
        self.error = "[!]"
        
    def createHasher(self, text : str, type_of_encrypt : str):
        """
        Hash Creator
        ~~~~~~~~~~~~~
        ```
        from BrupRocket import BrupRocket as br
        
        app = br()
        data = app.createHasher(text="Hello world", type_of_encrypt="md5")
        print(data)
        ```
        
        Available Type of hash: 
        
        `md5`
        `sha1`
        `sha256`
        `sha224`
        `sha512`
        `sha384`
        `sha3_256`
        
        or you can select a random type , just use "random" on parameter.
        
        """
        
        t = type_of_encrypt
        
        if t == "md5":
            md5 = self.hashlib.md5()
            md5.update(text.encode())
            return md5.hexdigest()
        
        elif (
            t == "sha1"
            ):
            sha1 = self.hashlib.sha1()
            sha1.update(
                text.encode()
                )
            return (
                sha1.hexdigest()
                )
        
        elif (
            t == "sha256"
            ):
            sha256 = self.hashlib.sha256()
            sha256.update(
                text.encode()
                )
            return (
                sha256.hexdigest()
                )
        
        elif (
            t == "sha224"
            ):
            sha224 = self.hashlib.sha224()
            sha224.update(
                text.encode()
                )
            return (
                sha224.hexdigest()
                )
        
        elif (
            t == "sha512"
            ):
            sha512 = self.hashlib.sha512()
            sha512.update(
                text.encode()
                )
            return (
                sha512.hexdigest()
                )
        
        elif (
            t == "sha384"
            ):
            sha384 = self.hashlib.sha384()
            sha384.update(
                text.encode()
                )
            return (
                sha384.hexdigest()
                )
        
        elif (
            t == "sha3_256"
            ):
            sha3_256 = self.hashlib.sha3_256()
            sha3_256.update(
                text.encode()
                )
            return (
                sha3_256.hexdigest()
                )
        
        elif (
            t == "sha3_224"
            ):
            sha3_224 = self.hashlib.sha3_224()
            sha3_224.update(
                text.encode()
                )
            return (
                sha3_224.hexdigest()
                )
        
        elif (
            t == "sha3_512"
            ):
            sha3_512 = self.hashlib.sha3_512()
            sha3_512.update(
                text.encode()
            )
            return (
                sha3_512.hexdigest()
            )
            
        elif (
            t == "sha3_384"
        ):
            sha3_384 = self.hashlib.sha3_384()
            sha3_384.update(
                text.encode()
            )
            return (
                sha3_384.hexdigest()
            )
            
        elif (
            t == "random"
        ):
            result = (
                random.choice(self.hashlist)
            )
            
            return BrupRocket().createHasher(text=text, type_of_encrypt=result)
        

            
            
    def getLocalIP(self):
        host = self.socket.gethostname()
        return self.socket.gethostbyname(host)
    
    def getDomainIP(self):
        return self.socket.gethostbyname(self.domain)
        
    def LaunchConsole(self):
        """
        Console
        ~~~~~~~
        """
        
        if len(sys.argv) <= 1:
            print(f"{self.note} {Help.usage()}")
        
        if "-v" in sys.argv:
            print(f'{self.note} 0.0.1')
            
        if "--version" in sys.argv:
            print(f'{self.note} 0.0.1')
            
        if '-h' in sys.argv:
            print(f'{self.note} {Help.usage()}')
            
        if "--help" in sys.argv:
            print(f'{self.note} {Help.usage()}')
            
        if "--get" in sys.argv:
            url_ = sys.argv.index('--get')+1
            urlz = sys.argv[url_]
            self.url = str(urlz)
            
            if "--header" in sys.argv:
                headerIndex = sys.argv.index("--header")+1
                headers = (sys.argv[headerIndex])
                
                if sys.argv[-1] == '--json':
                    try:
                        print(requests.get(url=self.url, headers=headers).json())
                        
                    except Exception as EJSONH:
                        print(f"{self.error} Error: {EJSONH}")
                    
                elif sys.argv[-1] == "--status":
                    try:
                        datash = requests.get(url=self.url, headers=headers).status_code
                        print(f"{self.true} {datash}")
                        
                    except Exception as ESH:
                        print(f"{self.error} Error: {ESH}")
                    
                elif sys.argv[-1] == "--body":
                    try:
                        databody = requests.get(url=self.url, headers=headers).text
                        print(f"{self.true} {databody}")
                        
                    except Exception as EBODYH:
                        print(f"{self.error} Error: {EBODYH}")
                    
                else:
                    try:
                        simpleH = requests.get(url=self.url, headers=headers).text
                        print(f"{self.true} {simpleH}")
                        
                    except Exception as ESIMH:
                        print(f"{self.error} Error: {ESIMH}")
                    
            else:
                if sys.argv[-1] == '--json':
                    try:
                        dataj = requests.get(url=self.url).json()
                        print(f"{self.true} {dataj}")
                    
                    except Exception as EDJ:
                        print(f"{self.error} {EDJ}")
                    
                elif sys.argv[-1] == "--status":
                    try:
                        print(f"{self.true} {requests.get(url=self.url).status_code}")
                        
                    except Exception as ESH:
                        print(f"{self.error} Error: {ESH}")
                    
                elif sys.argv[-1] == "--body":
                    try:
                        databody = requests.get(url=self.url).text
                        print(f"{self.true} {databody}")
                    
                    except Exception as EDB:
                        print(f"{self.error} {EDB}")
                    
                else:
                    try:
                        simple = requests.get(url=self.url).text
                        print(f"{self.true} {simple}")
                    except Exception as ES:
                        print(f"{self.error} {ES}")
                

        if "--post" in sys.argv:
            url_ = sys.argv.index('--post')+1
            urlxz = sys.argv[url_]
            self.url = str(urlxz)
            
            if "--header" in sys.argv:
                headerIndex = sys.argv.index("--header")+1
                headers = sys.argv[headerIndex]
                
                if sys.argv[-1] == '--json':
                    try:
                        datajh = requests.post(url=self.url, headers=headers).json()
                        print(f"{self.true} {datajh}")
                        
                    except Exception as EJSONH:
                        print(f"{self.error} Error: {EJSONH}")
                    
                elif sys.argv[-1] == "--status":
                    try:
                        datash = requests.post(url=self.url, headers=headers).status_code
                        print(f"{self.true} {datash}")
                        
                    except Exception as ESH:
                        print(f"{self.error} Error: {ESH}")
                    
                elif sys.argv[-1] == "--body":
                    try:
                        databody = requests.post(url=self.url, headers=headers).text
                        print(f"{self.true} {databody}")
                        
                    except Exception as EBODYH:
                        print(f"{self.error} Error: {EBODYH}")
                    
                else:
                    try:
                        simple = requests.post(url=self.url, headers=headers).text
                        print(f"{self.true} {simple}")
                        
                    except Exception as ESIMH:
                        print(f"{self.error} Error: {ESIMH}")
                    
            else:
                if sys.argv[-1] == '--json':
                    try:
                        dataj = requests.post(url=self.url).json()
                        print(f"{self.true} {dataj}")
                    
                    except Exception as EDJ:
                        print(f"{self.error} {EDJ}")
                    
                elif sys.argv[-1] == "--status":
                    datas = requests.post(url=self.url).status_code
                    print(f"{self.true} {datas}")

                    
                elif sys.argv[-1] == "--body":
                    try:
                        databody = requests.post(url=self.url).text
                        print(f"{self.true} {databody}")
                    
                    except Exception as EDB:
                        print(f"{self.error} {EDB}")
                    
                else:
                    try:
                        requests.post(url=self.url).text
                        print(f"{self.true} {simple}")
                    except Exception as ES:
                        print(f"{self.error} {ES}")
                    
        if "--hash" in sys.argv:
            if sys.argv[-2] == "--hash":
                print(BrupRocket().createHasher(sys.argv[-1], 'random'))
                
            if sys.argv[-2] == "--type":
                typeindex = sys.argv.index('--type')+1
                type_ = sys.argv[typeindex]
                
                print(BrupRocket().createHasher(sys.argv[-3], type_))
                
        if "--lolip" in sys.argv:
            print(
                self.getLocalIP()
            )
            
        if "--getip" in sys.argv:
            domain_ = sys.argv.index("--getip")+1
            self.domain = domain_
            print(
                self.getDomainIP
            )


