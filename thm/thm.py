"""
This script will renew tryhackme machine automatically.
Main functions are:
    1. Renew machine
    2. Generate SSH command for machine
    3. Start Machine if not running
    4. Restart machine if expired
"""
import requests
import time
import random
from pathlib import Path


class Machine:
    """Try Hackme me machine module"""

    def __init__(self, sid: str):
        self.session = requests.session()
        self.session.headers = {
            'authority': 'tryhackme.com',
            'accept': 'application/json, text/javascript, */*; q=0.01',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'accept-language': 'zh-TW,zh;q=0.9,en-US;q=0.8,en;q=0.7',
            'dnt': '1',
            'referer': 'https://tryhackme.com/my-machine',
            'csrf-token': 'oO8aBJUd-lXWOaAQwS6-KDaessmik2MjKB0g',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'sec-gpc': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
            'x-requested-with': 'XMLHttpRequest',
        }
        self.session.cookies.update(
            {
                '_csrf': 'pkoWyWdxsQm_OssN5UNh5jgg',
                'connect.sid': sid,
            }
        )
        self.machine_stats = None

    def check_stats(self) -> dict:
        """Check the machine running state"""
        response = self.session.get('https://tryhackme.com/api/vm/running')
        resp_data = response.json()
        print(f"[*] Running Machines(Raw) : \n{resp_data}\n")
        for r in resp_data:
            if r.get('roomId') == 'kali':
                return r

    def update_stats(self):
        """Update machine stats"""
        self.machine_stats = self.check_stats()

    def renew(self) -> dict:
        """Extend machine time"""
        data = {'code': 'kali'}
        response = self.session.post(
            'https://tryhackme.com/api/vm/renew', data=data)
        print(f"[*] Renew machine result: \n{response.text}")
        return response.json()

    def terminate(self) -> dict:
        """Terminate machine"""
        data = {'code': 'kali'}
        response = self.session.post(
            'https://tryhackme.com/api/vm/terminate', data=data)
        return response.json()

    def deploy(self) -> dict:
        """Deploy machine"""
        # Tryhackme attackbox id : 5f39eb6342e1ab8a6d900ba3
        data = {
            'id': '5f3a9d6842e1ab8a6de7f291',
            'roomCode': 'kali',
        }
        response = self.session.post(
            'https://tryhackme.com/material/deploy', data=data)
        return response.json()

    def parse_stats(self, machine_stats: dict = None) -> str:
        """Parse machine stats"""
        if not machine_stats:
            machine_stats = self.machine_stats
        creds = machine_stats.get('credentials')
        ip = machine_stats.get('internalIP')
        return f"""
        --------------------------------------------
        Machine           | {machine_stats.get('instanceId')}
        Expire In(Minute) | {int(machine_stats.get('timeInSeconds')) // 60}
        IP:               | {ip}
        Credentials:      | {":".join(creds.values())}
        SSH Command:      | sshpass -p {creds.get("password")} ssh {creds.get("username")}@{ip} -o "StrictHostKeyChecking no" 
        --------------------------------------------
        """


class MachineManager(Machine):
    """Machine manager"""

    def __init__(self, sid: str):
        super().__init__(sid)

    @property
    def session_id(self) -> str:
        """Get session id"""
        return self.session.cookies.get('connect.sid')
    
    @session_id.setter
    def session_id(self, sid: str):
        self.session.cookies.update({'connect.sid': sid})

    def get_stats(self):
        """Constantly check if machine IP is available after deploy"""
        while True:
            # Check if machine stats was fetched
            if not self.machine_stats:
                self.update_stats()
                time.sleep(5)
                continue

            #Check if machine's private IP is available
            if self.machine_stats.get('internalIP'):
                return self.parse_stats()

            print("---\n[*] Getting machine IP...")
            self.update_stats()
            time_to_wait = self.machine_stats.get('waitTime')
            print(f"[*] Waiting for {time_to_wait} seconds...")
            time.sleep(time_to_wait)
        

    def restart(self):
        """Restart machine by tetminate and deploy"""
        terminate_result = self.terminate()
        if not terminate_result.get('success'):
            print(
                f"[!] Machine terminate failed:\n***\n{terminate_result}\n***\n")
            return

        print(f"[*] Deploying new machine...\n")
        deploy_result = self.deploy()
        if not deploy_result.get('success'):
            print(
                f"[!] Machine deploy failed:\n***\n{deploy_result}\n***\n")
            return
        return True

    def remain(self):
        """Remain machine active"""
        print("\n[*] Checking machine stats...")
        try:
            self.update_stats()
        except requests.exceptions.JSONDecodeError:
            return False, "[!] Invalid cookie"

        # If machine is not running, deploy a new one
        if not self.machine_stats:
            print("[*] Machine is not running")
            start_machine_result = self.deploy()

            # If machine deploy failed, return
            if start_machine_result.get('success'):
                return True, "[+] Machine deployed"
            return False, "[!] Machine deploy failed"

        # If machine is running and going to expire in 1 hour
        if self.machine_stats.get('timeInSeconds') <= 3600:
            print("[*] Renewing machine...")
            renew_result = self.renew()

            # Successfully renewed
            if renew_result.get('success'):
                return True, f"\n[+] Machine renewed, time left: {renew_result.get('timeInSeconds')}\n"

            # Machine is going to expire but ran too long, have terminate and deploy a new one
            elif renew_result.get('msg') == "You have had your machine deployed for too long.":
                print("[!] Terminating Machine | Reason: Have Started over 3 Hours")
                if self.restart():
                    return True, "[+] Machine restarted"
            else:
                return False, "[!] Machine renew failed"

        return True, "[*] Machine is running"


def load_session_id() -> str:
    """Load session id from file"""
    with open('sid.txt', 'r') as f:
        return f.read().strip()


def save_session_id(session_id: str):
    """Save session id to file"""
    with open('sid.txt', 'w') as f:
        f.write(session_id.strip())


def get_session_id(override: bool = False):
    """Get session id from user input or file"""
    if not Path('sid.txt').exists() or override:
        session_id = input("Enter session id: ")
        save_session_id(session_id)
        return session_id
    return load_session_id()


def main():
    """Main function"""
    session_id = load_session_id()
    machine = MachineManager(sid=session_id)

    while 1:
        result, msg = machine.remain()
        print(msg)
        # If machine renew failed
        if not result:
            # If session id is invalid, get a new one
            if msg == "[!] Invalid cookie":
                print(f"***\n{machine.session.cookies}\n***\n")
                session_id = get_session_id(override=True)
                machine.session_id = session_id
                continue
            break

        print(machine.get_stats())
        sleep_for = random.randint(60, 300)
        print(f"[*] Sleeping for {sleep_for} seconds...")
        time.sleep(sleep_for)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] User Interrupted")
    finally:
        input("Press any key to exit...")
