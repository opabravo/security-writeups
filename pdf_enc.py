"""
Quick script to encrypt a PDF file.
"""
from pypdf import PdfWriter, PdfReader
from pathlib import Path
from dotenv import load_dotenv
from collections.abc import Iterable
import glob
import sys, os
import re
import requests


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
    """Get a list of PDF files in the directory"""
    for f in path.iterdir():
        if f.is_file() and f.suffix == ".pdf":
            yield f


def encrypt_pdf(pdf_file_path: Path, password: str):
    reader = PdfReader(pdf_file_path)
    if reader.is_encrypted:
        print(f"[*] {pdf_file_path} is already encrypted. Skipping ...")
        return
    writer = PdfWriter()

    print(f"[*] Encrypting {pdf_file} ... | {password}")
    # Loop over each page in the PDF file
    for page in reader.pages:
        writer.add_page(page)

    # Encrypt the PDF file
    print(f"[*] Encrypting {pdf_file_path} ... | {password}")
    writer.encrypt(password)

    # Save the new PDF to a file
    with open(pdf_file_path, "wb") as f:
        writer.write(f)


if __name__ == '__main__':
    token = os.getenv("HTB_TOKEN")
    password = os.getenv("PDF_PASSWORD")
    active_machines = [m["name"] for m in fetch_active_machines(token)]
    pdf_to_encrypt = [f for f in get_pdf_files(OUTPUT_MACHINE_PATH) if f.name.split(".")[0] in active_machines]

    print(f"[*] Active machines: {active_machines}")
    print(f"[*] PDF files to encrypt: {pdf_to_encrypt}")
    for pdf_file in pdf_to_encrypt:
        encrypt_pdf(pdf_file, password)
    print("---\n[*] Done!\n---")

