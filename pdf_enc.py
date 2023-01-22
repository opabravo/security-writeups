"""
This script will find flag from all PDF files and encrypt PDFs.
"""
from pypdf import PdfReader, PdfWriter, PageObject
from pathlib import Path
import glob
import re


def get_pdf_files(pdf_dir: str) -> list:
    """Get a list of all PDF files in the directory"""
    # Get a list of all PDF files in the current directory
    root_path = Path.cwd()
    source_pdf_path = root_path / pdf_dir
    return glob.glob(f"{source_pdf_path}/*.pdf")

def get_flag_from_pdf(page: PageObject) -> list:
    """Extract the root flag from the PDF file"""
    text = page.extract_text()
    return re.findall(r"([a-fA-F0-9]{32})", text)


def get_pdf_output_path(pdf_file) -> str:
    original_name = Path(pdf_file).name
    output_name = original_name.split("-")[1].strip()
    output_pdf_path = Path.cwd() / "htb" / "Machines"
    return f"{output_pdf_path}/{output_name}"


def encrypt_pdf(pdf_file):
    reader = PdfReader(pdf_file)
    writer = PdfWriter()

    # Loop over each page in the PDF file
    for page in reader.pages:
        if flags := get_flag_from_pdf(page):
            flag = flags[0]
        # print(f"[*] Found flag: {flag}")
        writer.add_page(page)

    # Encrypt the PDF file
    print(f"[*] Encrypting {pdf_file} ... | {flag}")
    writer.encrypt(flag)
    output_pdf_path = get_pdf_output_path(pdf_file)

    # Save the new PDF to a file
    with open(output_pdf_path, "wb") as f:
        writer.write(f)
    print(f"[+] Encrypted PDF saved to {output_pdf_path}\n")


if __name__ == "__main__":
    pdf_files = get_pdf_files("htb-unencrypted")

    # Loop over each PDF file
    for pdf_file in pdf_files:
        encrypt_pdf(pdf_file)

    input("Press any key to exit...")
