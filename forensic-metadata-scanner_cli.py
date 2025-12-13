import os
import datetime
import hashlib
from exiftool import ExifTool
from fpdf import FPDF

# === CONFIGURACIÓN DE SEGURIDAD ===
# Hash SHA256 de exiftool.exe oficial (el que tú confirmaste)
EXPECTED_HASH = "948606F43A90924315C117923F01F2FF8D242719E6398CB2800B9DB6EA5FC9FE"

class PDF(FPDF):
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()} - Generated on {datetime.datetime.now().strftime("%d/%m/%Y %H:%M")}', align='C')

def verify_exiftool():
    path = os.path.join(os.path.dirname(__file__), "exiftool.exe")
    if not os.path.isfile(path):
        print("ERROR: 'exiftool.exe' not found in the script directory.")
        return False

    try:
        with open(path, "rb") as f:
            calculated = hashlib.sha256(f.read()).hexdigest()
        if calculated.lower() != EXPECTED_HASH.lower():
            print("SECURITY ALERT!")
            print("exiftool.exe has been modified or does not match the official version.")
            print(f"Expected hash : {EXPECTED_HASH}")
            print(f"Calculated hash: {calculated}")
            print("Download the official version from https://exiftool.org/")
            return False
    except Exception as e:
        print(f"Could not verify exiftool.exe: {e}")
        return False

    return path

def generate_forensic_report(folder_path):
    exiftool_path = verify_exiftool()
    if not exiftool_path:
        return

    print(f"\nStarting forensic metadata analysis of:\n  {folder_path}\n")

    lines = []
    now = datetime.datetime.now().strftime('%d %B %Y, %H:%M:%S')

    lines.append(("FORENSIC METADATA ANALYSIS REPORT", "title"))
    lines.append(("-" * 70, "separator"))
    lines.append((f"Analyzed folder: {folder_path}", "section"))
    lines.append((f"Analysis date and time: {now}", "section"))
    lines.append(("Tool used: ExifTool", "section"))
    lines.append(("" , None))

    total_files = 0
    files_with_metadata = 0

    try:
        with ExifTool(executable=exiftool_path) as et:
            for root, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    total_files += 1

                    lines.append((f"File [{total_files}]: {file_path}", "file"))
                    lines.append(("-" * 90, "separator"))

                    try:
                        raw = et.execute_json(file_path)
                        if not raw or not raw[0]:
                            lines.append(("  No metadata found.", "value"))
                            continue

                        data = raw[0]

                        keys = [
                            'SourceFile', 'File:FileType', 'File:FileTypeExtension',
                            'File:FileModifyDate', 'File:FileCreateDate', 'File:FileAccessDate',
                            'File:ImageWidth', 'File:ImageHeight', 'File:FileSize', 'File:MIMEType',
                            'PNG:CreationTime', 'PNG:Software', 'PNG:Title', 'PNG:Author',
                        ]
                        extras = [k for k in data.keys() if any(k.startswith(p) for p in ['EXIF:', 'XMP:', 'IPTC:', 'ICC_Profile:'])]
                        keys.extend(extras)

                        found = 0
                        for k in keys:
                            if k in data:
                                value = str(data[k])
                                if len(value) > 300:
                                    value = value[:297] + "..."
                                lines.append((f"  {k}:", "key"))
                                lines.append((f"      {value}", "value"))
                                found += 1

                        if found > 0:
                            files_with_metadata += 1
                            lines.append((f"  -> {found} relevant metadata entries found.\n", "value"))
                            lines.append(("", None))
                        else:
                            lines.append(("  No relevant metadata found.\n", "value"))

                    except Exception as e:
                        lines.append((f"  ERROR: {e}", "error"))

        lines.append(("-" * 70, "separator"))
        summary = f"SUMMARY: {total_files} files processed | {files_with_metadata} with metadata"
        lines.append((summary, "summary"))
        lines.append(("Analysis completed successfully.", "summary"))

    except Exception as e:
        print(f"Error during analysis: {e}")
        return

    # === GENERAR PDF ===
    pdf_path = os.path.join(os.path.dirname(__file__), f"forensic_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")

    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    first_file = True

    for text, tag in lines:
        line = text.encode('latin-1', 'replace').decode('latin-1')

        if tag == "file":
            if not first_file:
                pdf.add_page()
            first_file = False
            pdf.set_font("Courier", 'B', 12)
            pdf.set_text_color(22, 101, 52)
            pdf.ln(5)
            pdf.multi_cell(0, 7, line)
            pdf.ln(3)
            continue

        if tag == "title":
            pdf.set_font("Helvetica", 'B', 16)
            pdf.set_text_color(0, 48, 135)
            pdf.multi_cell(0, 10, line, align='C')
            pdf.ln(8)
        elif tag == "section":
            pdf.set_font("Helvetica", 'B', 11)
            pdf.set_text_color(30, 64, 175)
            pdf.multi_cell(0, 6, line)
        elif tag == "key":
            pdf.set_font("Courier", 'B', 10)
            pdf.set_text_color(0, 0, 128)
            pdf.multi_cell(0, 5, line)
        elif tag == "value":
            pdf.set_font("Courier", size=10)
            pdf.set_text_color(51, 51, 51)
            pdf.multi_cell(0, 5, line)
        elif tag == "error":
            pdf.set_font("Courier", 'B', 10)
            pdf.set_text_color(200, 0, 0)
            pdf.multi_cell(0, 6, line)
        elif tag == "summary":
            pdf.set_font("Helvetica", 'B', 13)
            pdf.set_text_color(217, 70, 0)
            pdf.ln(10)
            pdf.multi_cell(0, 8, line, align='C')
        elif tag == "separator":
            pdf.set_text_color(170, 170, 170)
            pdf.multi_cell(0, 5, line)
        else:
            pdf.set_font("Courier", size=10)
            pdf.set_text_color(0, 0, 0)
            pdf.multi_cell(0, 5, line)

        pdf.set_text_color(0, 0, 0)

    pdf.output(pdf_path)
    print(f"\nAnalysis completed successfully!")
    print(f"Forensic report generated:\n  {os.path.abspath(pdf_path)}\n")

if __name__ == "__main__":
    print("Forensic Metadata Analyzer - Console Version")
    print("=" * 50)
    while True:
        folder = input("\nFolder to analyze: ").strip().strip('"\'')
        if os.path.isdir(folder):
            break
        print("That folder does not exist. Please try again.")
    
    generate_forensic_report(folder)