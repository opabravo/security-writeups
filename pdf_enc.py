"""
This script will find flag from all PDF files and encrypt PDFs.
"""
from pypdf import PdfReader, PdfWriter, PageObject
from pathlib import Path
import glob
import re


def get_flag_from_pdf(page: PageObject):
    """Extract the root flag from the PDF file"""
    # Get the text from the PDF page
    text = page.extract_text()
    # Find the flag in the text
    return re.findall(r"([a-fA-F0-9]{32})", text)


# Get a list of all PDF files in the current directory
root_path = Path.cwd()
source_pdf_path = root_path / "htb-unencrypted"
output_pdf_path = root_path / "htb" / "Machines"
pdf_files = glob.glob(f"{source_pdf_path}/*.pdf")
flag = ""

# Loop over each PDF file
for pdf_file in pdf_files:
    reader = PdfReader(pdf_file)
    writer = PdfWriter()

    # Loop over each page in the PDF file

    for page in reader.pages:
        if flags := get_flag_from_pdf(page):
            flag = flags[0]
        print(f"[*] Found flag: {flag}")
        # Add each page to the writer
        writer.add_page(page)

    # Encrypt the PDF file
    print(f"[*] Encrypting {pdf_file} ... | {flag}")
    writer.encrypt(flag)

    original_name = Path(pdf_file).name
    output_name = original_name.split("-")[1].strip()
    output_pdf_path = f"{output_pdf_path}/{output_name}"
    # Save the new PDF to a file
    with open(output_pdf_path, "wb") as f:
        writer.write(f)

    print(f"[+] Encrypted PDF saved to {output_pdf_path}")