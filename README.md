# Forensic Metadata Scanner
Python project for digital forensics, extracting and reporting file metadata
using **PyExifTool**, with both **CLI and GUI** interfaces and automatic **PDF
report generation**.

---

## Key Features
- Recursive folder analysis
- Advanced metadata extraction (EXIF, XMP, IPTC, ICC, File system)
- Uses **ExifTool installed on the system** (must be in PATH)
- Automatic generation of **forensic-grade PDF reports**
- Threaded execution in GUI mode to prevent interface blocking
- Structured, readable, court-ready reports
  
---

## Critical Requirement
This tool **requires ExifTool to be installed and accessible from the system
PATH**.
- Verify installation by running in CMD or PowerShell:
```
exiftool -ver
```
- The tool will **not function** if ExifTool is missing or not in PATH.
You can download the official Windows executable from:
[https://exiftool.org/](https://exiftool.org/)

---

## Installation
### Requirements
- Python 3.9 or newer
- Windows OS (due to ExifTool usage)
- ExifTool installed and accessible from PATH
### Python Dependencies
Install required libraries:
```
pip install -r requirements.txt
```
> `tkinter` is included by default in standard Python Windows installations.

---

## GUI Version Usage
Launch the graphical interface:
```
python forensic-metadata-scanner_gui.py
```
### GUI Workflow
1. Select the folder to analyze
2. Metadata analysis is performed recursively
3. Results are displayed in the interface
4. Export the forensic report as a PDF file
   
---

## CLI Version Usage
Run the console version:
```
python forensic-metadata-scanner_cli.py
```
### CLI Workflow
1. Enter the folder path when prompted
2. Metadata is extracted from all files recursively
3. A forensic PDF report is generated automatically
The output PDF is saved in the script directory:
```
forensic_report_YYYYMMDD_HHMMSS.pdf
```

---

## Metadata Categories Extracted
- File system timestamps
- File type and MIME information
- Image dimensions and properties
- EXIF metadata
- XMP metadata
- IPTC metadata
- ICC color profiles
> Additional metadata namespaces are included automatically when detected.

---

## Forensic Report Contents
- Case header and analysis timestamp
- Full file paths
- Extracted metadata (normalized and truncated if necessary)
- Per-file metadata count
- Final analysis summary
- Automatic pagination and footer timestamps
  
---

## Legal and Forensic Notice
This tool is intended for **lawful forensic analysis** only.
The author assumes **no responsibility** for misuse, improper handling of
evidence, or violations of privacy or local regulations.
Always ensure:
- Proper chain of custody
- Read-only access to original evidence
- Compliance with applicable laws and procedures
  
---

## License
This project is provided for educational and professional forensic use.
You may modify and adapt it for internal or investigative purposes. Attribution
is recommended.

---

## Author
Developed for professional digital forensic workflows using Python and ExifTool.

---
