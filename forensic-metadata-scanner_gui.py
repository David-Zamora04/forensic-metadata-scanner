import os
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
from exiftool import ExifTool
import threading
import datetime
import shutil
from fpdf import FPDF


class PDF(FPDF):
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(
            0, 10,
            f'Page {self.page_no()} - Generated on {datetime.datetime.now().strftime("%d/%m/%Y %H:%M")}',
            align='C'
        )


class ForensicAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Forensic Metadata Analyzer - Professional")
        self.root.geometry("1000x750")
        self.root.minsize(900, 650)

        self.folder_path = tk.StringVar()
        self.exiftool_path = None
        self.thread_process = None
        self.report_lines = []

        self.create_interface()
        self.locate_exiftool()

    def locate_exiftool(self):
        self.exiftool_path = shutil.which("exiftool")
        if not self.exiftool_path:
            messagebox.showerror(
                "ExifTool Not Found",
                "ExifTool is not installed or not in the system PATH.\n\n"
                "Test it by running:\n\n"
                "  exiftool -ver"
            )
            self.root.destroy()

    def create_interface(self):
        style = ttk.Style()
        style.theme_use('clam')

        frame_top = ttk.Frame(self.root, padding="15")
        frame_top.pack(fill=tk.X)

        ttk.Label(frame_top, text="Folder to analyze:", font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Entry(frame_top, textvariable=self.folder_path, width=80, font=("Segoe UI", 10)).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        ttk.Button(frame_top, text="Browse...", command=self.select_folder).pack(side=tk.LEFT)

        frame_buttons = ttk.Frame(self.root, padding="10")
        frame_buttons.pack(pady=10)

        self.btn_start = ttk.Button(frame_buttons, text="Start Forensic Analysis", command=self.start_analysis)
        self.btn_start.pack(side=tk.LEFT, padx=(0, 15))

        self.btn_save = ttk.Button(frame_buttons, text="Export PDF Report", command=self.save_pdf_report, state=tk.DISABLED)
        self.btn_save.pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(self.root, mode='indeterminate', length=500)
        self.progress.pack(pady=10)

        ttk.Label(self.root, text="Detailed Forensic Report", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=20, pady=(15, 5))
        self.text_report = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, font=("Consolas", 10), bg="white")
        self.text_report.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        self.text_report.tag_config("title", foreground="#003087", font=("Segoe UI", 14, "bold"), justify="center")
        self.text_report.tag_config("section", foreground="#1e40af", font=("Segoe UI", 11, "bold"))
        self.text_report.tag_config("file", foreground="#166534", font=("Consolas", 11, "bold"))
        self.text_report.tag_config("key", foreground="#000080", font=("Consolas", 10, "bold"))
        self.text_report.tag_config("value", foreground="#333333", font=("Consolas", 10))
        self.text_report.tag_config("error", foreground="red", font=("Consolas", 10, "bold"))
        self.text_report.tag_config("summary", foreground="#d94600", font=("Segoe UI", 11, "bold"))
        self.text_report.tag_config("separator", foreground="#aaaaaa")

        self.label_stats = ttk.Label(self.root, text="", font=("Segoe UI", 10, "italic"), foreground="#444444")
        self.label_stats.pack(pady=5)

    def select_folder(self):
        folder = filedialog.askdirectory(title="Select folder for forensic analysis")
        if folder:
            self.folder_path.set(folder)

    def start_analysis(self):
        folder = self.folder_path.get().strip().strip('"\'')
        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Error", "Select a valid folder.")
            return

        self.text_report.delete(1.0, tk.END)
        self.report_lines = []
        self.label_stats.config(text="")
        self.btn_start.config(state=tk.DISABLED)
        self.btn_save.config(state=tk.DISABLED)
        self.progress.start(15)

        self.thread_process = threading.Thread(
            target=self.generate_forensic_report,
            args=(folder,),
            daemon=True
        )
        self.thread_process.start()

    def write(self, text, tag=None):
        self.text_report.insert(tk.END, text + "\n", tag)
        self.report_lines.append((text, tag))
        self.text_report.see(tk.END)
        self.root.update_idletasks()

    def generate_forensic_report(self, folder):
        try:
            now = datetime.datetime.now().strftime('%d %B %Y, %H:%M:%S')

            self.write("DIGITAL FORENSIC REPORT - METADATA ANALYSIS", "title")
            self.write("-" * 70, "separator")
            self.write(f"Analyzed folder: {folder}", "section")
            self.write(f"Analysis date and time: {now}", "section")
            self.write("Tool used: ExifTool", "section")
            self.write("")

            total = 0
            with_metadata = 0

            with ExifTool(executable=self.exiftool_path) as et:
                for root, _, files in os.walk(folder):
                    for file in files:
                        path = os.path.join(root, file)
                        total += 1

                        self.write(f"File [{total}]: {path}", "file")
                        self.write("-" * 90, "separator")

                        try:
                            raw = et.execute_json(path)
                            if not raw or not raw[0]:
                                self.write("  No metadata found.", "value")
                                continue

                            data = raw[0]

                            keys = [
                                'SourceFile', 'File:FileType', 'File:FileTypeExtension',
                                'File:FileModifyDate', 'File:FileCreateDate', 'File:FileAccessDate',
                                'File:ImageWidth', 'File:ImageHeight', 'File:FileSize', 'File:MIMEType',
                                'PNG:CreationTime', 'PNG:Software', 'PNG:Title', 'PNG:Author',
                            ]

                            extras = [
                                k for k in data.keys()
                                if k.startswith(('EXIF:', 'XMP:', 'IPTC:', 'ICC_Profile:'))
                            ]
                            keys.extend(extras)

                            found = 0
                            for k in keys:
                                if k in data:
                                    value = str(data[k])
                                    if len(value) > 300:
                                        value = value[:297] + "..."
                                    self.write(f"  {k}:", "key")
                                    self.write(f"      {value}", "value")
                                    found += 1

                            if found:
                                with_metadata += 1
                                self.write(f"  -> {found} relevant metadata entries found.\n", "value")
                            else:
                                self.write("  No relevant metadata.\n", "value")

                        except Exception as e:
                            self.write(f"  ERROR: {e}", "error")

            self.write("-" * 70, "separator")
            summary = f"SUMMARY: {total} files processed | {with_metadata} with metadata"
            self.write(summary, "summary")
            self.write("Analysis completed successfully.", "summary")

            self.root.after(0, self.label_stats.config, {'text': summary})

        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", str(e))
        finally:
            self.root.after(0, self.finish_analysis)

    def finish_analysis(self):
        self.progress.stop()
        self.progress.pack_forget()
        self.btn_start.config(state=tk.NORMAL)
        self.btn_save.config(state=tk.NORMAL)
        messagebox.showinfo("Completed", "Analysis finished. You can export the report to PDF.")

    def save_pdf_report(self):
        file_path = filedialog.asksaveasfilename(
            title="Export Forensic Report",
            defaultextension=".pdf",
            filetypes=[("PDF Document", "*.pdf")],
            initialfile=f"forensic_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        )
        if not file_path:
            return

        try:
            pdf = PDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()

            first_file = True

            for text, tag in self.report_lines:
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

            pdf.output(file_path)
            messagebox.showinfo("Exported", f"PDF report successfully generated:\n{file_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate PDF:\n{e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = ForensicAnalyzerGUI(root)
    root.mainloop()
