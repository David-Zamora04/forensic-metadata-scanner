# forensic-metadata-scanner

Python script for digital forensics, extracting and reporting file metadata using **PyExifTool**, with both **CLI and GUI** interfaces and automatic **PDF report generation**.

---

## Key Features

* Recursive folder analysis
* Advanced metadata extraction (EXIF, XMP, IPTC, ICC, File system)
* Mandatory **SHA-256 integrity verification of `exiftool.exe`**
* Automatic generation of **forensic-grade PDF reports**
* Threaded execution in GUI mode to prevent interface blocking
* Structured, readable, court-ready reports

---

---

## Critical Security Requirement

This project **will not execute** unless the integrity of `exiftool.exe` is verified.

* The tool computes the **SHA-256 hash** of `exiftool.exe`
* Execution is **blocked** if the hash does not match the expected official value
* This prevents execution of **tampered or malicious binaries**

You must download the official Windows executable from:

[https://exiftool.org/](https://exiftool.org/)

And ensure it matches the following hash:

```text
948606F43A90924315C117923F01F2FF8D242719E6398CB2800B9DB6EA5FC9FE
```

---

## Installation

### Requirements

* Python 3.9 or newer
* Windows OS (due to `exiftool.exe` usage)

### Python Dependencies

Install required libraries:

```bash
pip install pyexiftool fpdf
```

`tkinter` is included by default in standard Python Windows installations.

---

## GUI Version Usage

Launch the graphical interface:

```bash
python analyzer_gui.py
```

### GUI Workflow

1. Select the folder to analyze
2. The tool verifies the integrity of `exiftool.exe`
3. Metadata analysis is performed recursively
4. Results are displayed in the interface
5. Export the forensic report as a PDF file

---

## CLI Version Usage

Run the console version:

```bash
python analyzer_cli.py
```

### CLI Workflow

1. Enter the folder path when prompted
2. The tool verifies `exiftool.exe`
3. Metadata is extracted from all files
4. A forensic PDF report is generated automatically

The output PDF is saved in the script directory:

```text
forensic_report_YYYYMMDD_HHMMSS.pdf
```

---

## Metadata Categories Extracted

* File system timestamps
* File type and MIME information
* Image dimensions and properties
* EXIF metadata
* XMP metadata
* IPTC metadata
* ICC color profiles

Additional metadata namespaces are included automatically when detected.

---

## Forensic Report Contents

* Case header and analysis timestamp
* Full file paths
* Extracted metadata (normalized and truncated if necessary)
* Per-file metadata count
* Final analysis summary
* Automatic pagination and footer timestamps

---

## Legal and Forensic Notice

This tool is intended for **lawful forensic analysis** only.

The author assumes **no responsibility** for misuse, improper handling of evidence, or violations of privacy or local regulations.

Always ensure:

* Proper chain of custody
* Read-only access to original evidence
* Compliance with applicable laws and procedures

---

## License

This project is provided for educational and professional forensic use.

You may modify and adapt it for internal or investigative purposes. Attribution is recommended.

---

## Author

Developed for professional digital forensic workflows using Python and ExifTool.

