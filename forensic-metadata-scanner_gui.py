import os
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, ttk
from exiftool import ExifTool
import threading
import datetime
import hashlib 
from fpdf import FPDF

HASH_ESPERADO = "948606F43A90924315C117923F01F2FF8D242719E6398CB2800B9DB6EA5FC9FE"

# Clase PDF con pie de página automático
class PDF(FPDF):
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Página {self.page_no()} - Generado el {datetime.datetime.now().strftime("%d/%m/%Y %H:%M")}', align='C')

class AnalizadorForenseGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Analizador Forense de Metadatos - Profesional")
        self.root.geometry("1000x750")
        self.root.minsize(900, 650)

        self.ruta_carpeta = tk.StringVar()
        self.ruta_exiftool = None
        self.proceso_hilo = None
        self.informe_lineas = []

        self.crear_interfaz()

    def verificar_exiftool_integridad(self):
        ruta = os.path.join(os.path.dirname(__file__), "exiftool.exe")
        if not os.path.isfile(ruta):
            messagebox.showerror("Seguridad", "No se encontró 'exiftool.exe' en la carpeta del script.")
            return False

        try:
            with open(ruta, "rb") as f:
                hash_calculado = hashlib.sha256(f.read()).hexdigest()
            if hash_calculado.lower() != HASH_ESPERADO.lower():
                messagebox.showerror(
                    "¡ALERTA DE SEGURIDAD!",
                    "El archivo 'exiftool.exe' ha sido modificado o no coincide con la versión oficial.\n"
                    "Hash esperado: " + HASH_ESPERADO + "\n"
                    "Hash calculado: " + hash_calculado + "\n\n"
                    "La herramienta NO se ejecutará por seguridad.\n"
                    "Descarga exiftool.exe desde https://exiftool.org/"
                )
                return False
        except Exception as e:
            messagebox.showerror("Error de verificación", f"No se pudo verificar exiftool.exe:\n{e}")
            return False

        return True

    def crear_interfaz(self):
        style = ttk.Style()
        style.theme_use('clam')

        frame_top = ttk.Frame(self.root, padding="15")
        frame_top.pack(fill=tk.X)

        ttk.Label(frame_top, text="Carpeta a analizar:", font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Entry(frame_top, textvariable=self.ruta_carpeta, width=80, font=("Segoe UI", 10)).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        ttk.Button(frame_top, text="Examinar...", command=self.seleccionar_carpeta).pack(side=tk.LEFT)

        frame_botones = ttk.Frame(self.root, padding="10")
        frame_botones.pack(pady=10)

        self.btn_iniciar = ttk.Button(frame_botones, text="Iniciar Análisis Forense", command=self.iniciar_analisis)
        self.btn_iniciar.pack(side=tk.LEFT, padx=(0, 15))

        self.btn_guardar = ttk.Button(frame_botones, text="Exportar Informe PDF", command=self.guardar_informe_pdf, state=tk.DISABLED)
        self.btn_guardar.pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(self.root, mode='indeterminate', length=500)
        self.progress.pack(pady=10)

        ttk.Label(self.root, text="Informe Forense Detallado", font=("Segoe UI", 12, "bold")).pack(anchor=tk.W, padx=20, pady=(15, 5))
        self.texto_informe = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, font=("Consolas", 10), bg="white")
        self.texto_informe.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))

        self.texto_informe.tag_config("titulo", foreground="#003087", font=("Segoe UI", 14, "bold"), justify="center")
        self.texto_informe.tag_config("seccion", foreground="#1e40af", font=("Segoe UI", 11, "bold"))
        self.texto_informe.tag_config("archivo", foreground="#166534", font=("Consolas", 11, "bold"))
        self.texto_informe.tag_config("clave", foreground="#000080", font=("Consolas", 10, "bold"))
        self.texto_informe.tag_config("valor", foreground="#333333", font=("Consolas", 10))
        self.texto_informe.tag_config("error", foreground="red", font=("Consolas", 10, "bold"))
        self.texto_informe.tag_config("resumen", foreground="#d94600", font=("Segoe UI", 11, "bold"))
        self.texto_informe.tag_config("separador", foreground="#aaaaaa")

        self.label_stats = ttk.Label(self.root, text="", font=("Segoe UI", 10, "italic"), foreground="#444444")
        self.label_stats.pack(pady=5)

    def seleccionar_carpeta(self):
        carpeta = filedialog.askdirectory(title="Seleccionar carpeta para análisis forense")
        if carpeta:
            self.ruta_carpeta.set(carpeta)

    def iniciar_analisis(self):
        carpeta = self.ruta_carpeta.get().strip().strip('"\'')
        if not carpeta or not os.path.isdir(carpeta):
            messagebox.showerror("Error", "Selecciona una carpeta válida.")
            return

        # === VERIFICACIÓN DE SEGURIDAD ===
        if not self.verificar_exiftool_integridad():
            return  # Bloquea el análisis si falla

        self.ruta_exiftool = os.path.join(os.path.dirname(__file__), "exiftool.exe")

        self.texto_informe.delete(1.0, tk.END)
        self.informe_lineas = []
        self.label_stats.config(text="")
        self.btn_iniciar.config(state=tk.DISABLED)
        self.btn_guardar.config(state=tk.DISABLED)
        self.progress.start(15)

        self.proceso_hilo = threading.Thread(target=self.generar_informe_forense, args=(carpeta,), daemon=True)
        self.proceso_hilo.start()

    def escribir(self, texto, tag=None):
        self.texto_informe.insert(tk.END, texto + "\n", tag)
        self.informe_lineas.append((texto, tag))
        self.texto_informe.see(tk.END)
        self.root.update_idletasks()

    def generar_informe_forense(self, ruta_carpeta):
        # ... (el resto del código de generación del informe es idéntico al anterior)
        # (Lo mantengo igual para no alargar, pero puedes copiarlo del mensaje anterior)
        try:
            ahora = datetime.datetime.now().strftime('%d de %B de %Y, %H:%M:%S')
            self.escribir("INFORME FORENSE DIGITAL - ANALISIS DE METADATOS", "titulo")
            self.escribir("-" * 70, "separador")
            self.escribir(f"Carpeta analizada: {ruta_carpeta}", "seccion")
            self.escribir(f"Fecha y hora del analisis: {ahora}", "seccion")
            self.escribir(f"Herramienta utilizada: ExifTool", "seccion")
            self.escribir("")

            total = 0
            con_meta = 0

            with ExifTool(executable=self.ruta_exiftool) as et:
                for raiz, _, archivos in os.walk(ruta_carpeta):
                    for archivo in archivos:
                        ruta = os.path.join(raiz, archivo)
                        total += 1

                        self.escribir(f"Archivo [{total}]: {ruta}", "archivo")
                        self.escribir("-" * 90, "separador")

                        try:
                            raw = et.execute_json(ruta)
                            if not raw or not raw[0]:
                                self.escribir("  No se encontraron metadatos.", "valor")
                                continue

                            datos = raw[0]

                            claves = [
                                'SourceFile', 'File:FileType', 'File:FileTypeExtension',
                                'File:FileModifyDate', 'File:FileCreateDate', 'File:FileAccessDate',
                                'File:ImageWidth', 'File:ImageHeight', 'File:FileSize', 'File:MIMEType',
                                'PNG:CreationTime', 'PNG:Software', 'PNG:Title', 'PNG:Author',
                            ]
                            extras = [k for k in datos.keys() if any(k.startswith(p) for p in ['EXIF:', 'XMP:', 'IPTC:', 'ICC_Profile:'])]
                            claves.extend(extras)

                            encontrados = 0
                            for k in claves:
                                if k in datos:
                                    valor = str(datos[k])
                                    if len(valor) > 300:
                                        valor = valor[:297] + "..."
                                    self.escribir(f"  {k}:", "clave")
                                    self.escribir(f"      {valor}", "valor")
                                    encontrados += 1

                            if encontrados > 0:
                                con_meta += 1
                                self.escribir(f"  -> {encontrados} metadatos relevantes encontrados.\n", "valor")
                            else:
                                self.escribir("  No hay metadatos relevantes.\n", "valor")

                        except Exception as e:
                            self.escribir(f"  ERROR: {e}", "error")

            self.escribir("-" * 70, "separador")
            resumen = f"RESUMEN: {total} archivos procesados | {con_meta} con metadatos"
            self.escribir(resumen, "resumen")
            self.escribir("Análisis completado con éxito.", "resumen")

            self.root.after(0, self.label_stats.config, {'text': resumen})

        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", f"{e}")
        finally:
            self.root.after(0, self.finalizar_analisis)

    def finalizar_analisis(self):
        self.progress.stop()
        self.progress.pack_forget()
        self.btn_iniciar.config(state=tk.NORMAL)
        self.btn_guardar.config(state=tk.NORMAL)
        messagebox.showinfo("Completado", "Análisis finalizado. Puedes exportar el informe en PDF.")

    def guardar_informe_pdf(self):
        # ... (igual que en la versión anterior con la clase PDF y sin página en blanco)
        archivo = filedialog.asksaveasfilename(
            title="Exportar Informe Forense",
            defaultextension=".pdf",
            filetypes=[("Documento PDF", "*.pdf")],
            initialfile=f"informe_forense_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        )
        if not archivo:
            return

        try:
            pdf = PDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()

            primer_archivo = True

            for texto, tag in self.informe_lineas:
                linea = texto.encode('latin-1', 'replace').decode('latin-1')

                if tag == "archivo":
                    if not primer_archivo:
                        pdf.add_page()
                    primer_archivo = False

                    pdf.set_font("Courier", 'B', 12)
                    pdf.set_text_color(22, 101, 52)
                    pdf.ln(5)
                    pdf.multi_cell(0, 7, linea)
                    pdf.ln(3)
                    continue

                if tag == "titulo":
                    pdf.set_font("Helvetica", 'B', 16)
                    pdf.set_text_color(0, 48, 135)
                    pdf.multi_cell(0, 10, linea, align='C')
                    pdf.ln(8)
                elif tag == "seccion":
                    pdf.set_font("Helvetica", 'B', 11)
                    pdf.set_text_color(30, 64, 175)
                    pdf.multi_cell(0, 6, linea)
                elif tag == "clave":
                    pdf.set_font("Courier", 'B', 10)
                    pdf.set_text_color(0, 0, 128)
                    pdf.multi_cell(0, 5, linea)
                elif tag == "valor":
                    pdf.set_font("Courier", size=10)
                    pdf.set_text_color(51, 51, 51)
                    pdf.multi_cell(0, 5, linea)
                elif tag == "error":
                    pdf.set_font("Courier", 'B', 10)
                    pdf.set_text_color(200, 0, 0)
                    pdf.multi_cell(0, 6, linea)
                elif tag == "resumen":
                    pdf.set_font("Helvetica", 'B', 13)
                    pdf.set_text_color(217, 70, 0)
                    pdf.ln(10)
                    pdf.multi_cell(0, 8, linea, align='C')
                elif tag == "separador":
                    pdf.set_text_color(170, 170, 170)
                    pdf.multi_cell(0, 5, linea)
                else:
                    pdf.set_font("Courier", size=10)
                    pdf.set_text_color(0, 0, 0)
                    pdf.multi_cell(0, 5, linea)

                pdf.set_text_color(0, 0, 0)

            pdf.output(archivo)
            messagebox.showinfo("Exportado", f"Informe PDF generado correctamente:\n{archivo}")

        except Exception as e:
            messagebox.showerror("Error", f"No se pudo generar el PDF:\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AnalizadorForenseGUI(root)
    root.mainloop()