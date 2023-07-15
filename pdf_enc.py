"""
A script to automatically encrypt and decrypt hack the box PDF writeups based on machine/challenge active/retired status.
"""
import os, contextlib
import requests
from pypdf import PdfWriter, PdfReader
from pathlib import Path
from dotenv import load_dotenv
from collections.abc import Iterable



load_dotenv()
BASE_PATH = Path(__file__).parent.resolve()
OUTPUT_MACHINE_PATH = BASE_PATH / "htb" / "Machines"
OUTPUT_CHALLENGE_PATH = BASE_PATH / "htb" / "Challenges"


def fetch_active_machines(token: str) -> list:
    """
    Fetch active machines from HTB API
    """
    url = "https://www.hackthebox.com/api/v4/machine/list"
    headers = {"Authorization": f"Bearer {token}",
               "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"}
    response = requests.get(url, headers=headers)
    result = response.json()
    return result["info"]


def get_pdf_files(path: Path) -> Iterable[Path]:
    """Get a list of PDF files in the directory recrusively"""
    return path.glob("**/*.pdf")


def encrypt_pdf(pdf_file_path: Path, password: str) -> bool:
    reader = PdfReader(pdf_file_path)
    if reader.is_encrypted:
        print(f"[*] {pdf_file_path} is already encrypted. Skipping ...")
        return False
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    writer.encrypt(password)

    with open(pdf_file_path, "wb") as f:
        writer.write(f)
        
    print(f"[+] Done encrypting | {pdf_file_path}")
    return True
        

def decrypt_pdf(pdf_file_path : Path, password: str) -> bool:
    """Decrypt a PDF file if it is encrypted"""
    reader = PdfReader(pdf_file_path)
    if not reader.is_encrypted:
        return False
    
    reader.decrypt(password)
    writer = PdfWriter()
    
    for page in reader.pages:
        writer.add_page(page)
        
    with open(pdf_file_path, "wb") as f:
        writer.write(f)
        
    print(f"[+] Done decrypting | {pdf_file_path}")
    return True

def adjust_pdf_file_name(path: Path):
    """Remove Hack The Box Writeup prefix from pdf file names"""
    pdf_files = get_pdf_files(path)
    prefix = "HackTheBox Writeup - "
    for pdf_file in pdf_files:
        if pdf_file.name.startswith(prefix):
            new_name = pdf_file.name.replace(prefix, "")
            pdf_file.rename(pdf_file.parent / new_name)
            print(f"[+] Renamed {pdf_file.name} to {new_name}")
        
def main():
    """Main entry point to decrypt or encrypt PDF files"""
    TOKEN = os.getenv("HTB_TOKEN")
    PASSWORD = os.getenv("PDF_PASSWORD")
    
    active_machines = [m["name"].lower() for m in fetch_active_machines(TOKEN)]
    adjust_pdf_file_name(OUTPUT_MACHINE_PATH)
    existed_machine_files = get_pdf_files(OUTPUT_MACHINE_PATH)
    
    pdf_to_encrypt = [f for f in existed_machine_files if f.name.split(".")[0].lower() in active_machines]
    pdf_to_decrypt = [f for f in existed_machine_files if f not in pdf_to_encrypt]

    print(f"[*] Active machines: {active_machines}")
    print(f"[*] PDF files to encrypt: {pdf_to_encrypt}")
    print(f"[*] PDF files to decrypt: {pdf_to_decrypt}")
    
    print("---\n[*] Starting ...\n---")
    
    for pdf_file in pdf_to_encrypt:
        print(f"[*] Encrypting {pdf_file} ... | {PASSWORD}")
        encrypt_pdf(pdf_file, PASSWORD)
        
    for pdf_file in pdf_to_decrypt:
        print(f"[*] Decrypting {pdf_file} ... | {PASSWORD}")
        decrypt_pdf(pdf_file, PASSWORD)
        
    print("---\n[*] Done!\n---")


if __name__ == '__main__':
    with contextlib.suppress(KeyboardInterrupt):
        main()
    input("Press any key to exit ...")

