"""
This script will find flag from all PDF files and encrypt PDFs.
"""
from pypdf import PdfReader, PdfWriter, PageObject
from pathlib import Path
import glob
import re

BASE_PATH = Path(__file__).parent.resolve()
OUTPUT_MACHINE_PATH = BASE_PATH / "htb" / "Machines"
OUTPUT_CHALLENGE_PATH = BASE_PATH / "htb" / "Challenges"


def get_pdf_files(pdf_dir: str) -> GeneratorExit:
    """Get a list of all PDF files in the directory"""
    # Get a list of all PDF files in the current directory
    source_pdf_path = Path.cwd() / pdf_dir
    yield from glob.glob(f"{source_pdf_path}/*.pdf")


def get_flag_from_page(page: PageObject) -> list:
    """Extract the root flag from the PDF file"""
    text = page.extract_text()
    return re.findall(r"([a-fA-F0-9]{32})", text)


def get_machine_output_path(pdf_file: str) -> Path:
    """Rename the original machine PDF file to the machine name only"""
    original_name = Path(pdf_file).name
    output_name = original_name.split("-")[1].strip()
    return OUTPUT_MACHINE_PATH / output_name


def encrypt_pdf(pdf_file: str, output_path: str):
    reader = PdfReader(pdf_file)
    writer = PdfWriter()

    # Loop over each page in the PDF file
    for page in reader.pages:
        if flags := get_flag_from_page(page):
            flag = flags[0]
        # print(f"[*] Found flag: {flag}")
        writer.add_page(page)

    # Encrypt the PDF file
    print(f"[*] Encrypting {pdf_file} ... | {flag}")
    writer.encrypt(flag)

    # Save the new PDF to a file
    with open(output_path, "wb") as f:
        writer.write(f)


def encrypt_machines():
    """Encrypt machines PDFs under htb-unencrypted directory"""
    print("---\n[*] Encrypting machines PDFs...\n---")
    # Loop over each PDF file
    dir_path = BASE_PATH / "htb-unencrypted" / "Machines"
    for pdf_file in get_pdf_files(dir_path):
        output_pdf_path = get_machine_output_path(pdf_file)
        # Check if the output PDF file already exists
        if output_pdf_path.exists():
            print(f"[!] {output_pdf_path} already exists. Skipping...")
            continue

        encrypt_pdf(pdf_file, output_pdf_path)
        print(f"[+] Encrypted PDF saved to {output_pdf_path}\n")


def encrypt_challenges():
    """Encrypt challenges PDFs under challenges-unencrypted directory"""
    print("---\n[*] Encrypting challenges PDFs...\n---")
    dir_path = BASE_PATH / "htb-unencrypted" / "Challenges"
    # Loop over each PDF file
    for pdf_file in get_pdf_files(dir_path):
        output_pdf_path = OUTPUT_CHALLENGE_PATH / Path(pdf_file).name
        # Check if the output PDF file already exists
        if output_pdf_path.exists():
            print(f"[!] {output_pdf_path} already exists. Skipping...")
            continue

        encrypt_pdf(pdf_file, output_pdf_path)
        print(f"[+] Encrypted PDF saved to {output_pdf_path}\n")


if __name__ == "__main__":
    encrypt_machines()
    input("Press any key to exit...")
