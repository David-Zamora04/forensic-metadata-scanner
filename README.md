# Forensic Metadata Scanner

Python project for digital forensics, extracting and reporting file metadata using **PyExifTool**, with both **CLI and GUI** interfaces and automatic **PDF report generation**.

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

This tool **requires ExifTool to be installed and accessible from the system PATH**.  

- Verify installation by running in CMD or PowerShell:

```cmd
exiftool -ver
