import cv2
import time
from pyzbar import pyzbar
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk, ImageGrab
import threading
import queue
import logging
import numpy as np

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class ModernQRScanner:
    def __init__(self, window, window_title):
        self.window = window
        self.window.title(window_title)
        self.window.geometry("1800x850")  # Set initial window size
        self.window.configure(bg='#2C3E50')
        
        # Center the window on the screen
        self.center_window()
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.configure_styles()
        
        self.vid = None
        self.is_scanning_webcam = False
        self.is_scanning_monitor = False
        self.last_code_webcam = ""
        self.last_code_monitor = ""
        self.last_time_webcam = 0
        self.last_time_monitor = 0
        self.log_webcam = []
        self.log_monitor = []
        self.frame_queue_webcam = queue.Queue(maxsize=1)
        self.frame_queue_monitor = queue.Queue(maxsize=1)
        
        self.create_widgets()
        self.create_layout()
        
        self.delay = 15
        self.update()
        
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        logging.info("ModernQRScanner initialized")
        self.update_status_webcam("Ready to scan. Click 'Start Scanning' to begin.")
        self.update_status_monitor("Ready to scan. Click 'Start Scanning' to begin.")

    def center_window(self):
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry('{}x{}+{}+{}'.format(width, height, x, y))

    def configure_styles(self):
        try:
            self.style.configure('TButton', font=('Helvetica', 12), padding=10)
            self.style.configure('TLabel', font=('Helvetica', 12), background='#2C3E50', foreground='white')
            self.style.configure('Header.TLabel', font=('Helvetica', 20, 'bold'), background='#2C3E50', foreground='#ECF0F1')
            self.style.configure('TFrame', background='#2C3E50')
            
            # Configure button colors
            self.style.map('TButton',
                background=[('active', '#34495E'), ('!disabled', '#3498DB')],
                foreground=[('!disabled', 'white')]
            )
            
            # Configure canvas style
            self.style.configure('Canvas.TFrame', background='#34495E')
            
            logging.info("Styles configured successfully")
        except Exception as e:
            logging.error(f"Error configuring styles: {str(e)}")
            self.show_error("Style Configuration Error", str(e))

    def create_widgets(self):
        self.main_frame = ttk.Frame(self.window, padding="20")
        
        self.header_label = ttk.Label(self.main_frame, text="Modern macOS QR-Code Scanner", style='Header.TLabel')
        
        # Webcam frame
        self.webcam_frame = ttk.Frame(self.main_frame)
        self.webcam_canvas = tk.Canvas(self.webcam_frame, width=640, height=480, bg='#34495E', highlightthickness=0)
        self.webcam_button_frame = ttk.Frame(self.webcam_frame)
        self.btn_start_stop_webcam = ttk.Button(self.webcam_button_frame, text="Start Webcam Scanning", width=20, command=self.start_stop_webcam)
        self.btn_export_webcam = ttk.Button(self.webcam_button_frame, text="Export Webcam Log", width=20, command=lambda: self.export_log(self.log_webcam))
        self.btn_clear_webcam = ttk.Button(self.webcam_button_frame, text="Clear Webcam Log", width=20, command=lambda: self.clear_log(self.log_webcam, self.log_text_webcam))
        self.status_var_webcam = tk.StringVar()
        self.status_label_webcam = ttk.Label(self.webcam_button_frame, textvariable=self.status_var_webcam, font=('Helvetica', 12))
        
        # Monitor frame
        self.monitor_frame = ttk.Frame(self.main_frame)
        self.monitor_canvas = tk.Canvas(self.monitor_frame, width=640, height=480, bg='#34495E', highlightthickness=0)
        self.monitor_button_frame = ttk.Frame(self.monitor_frame)
        self.btn_start_stop_monitor = ttk.Button(self.monitor_button_frame, text="Start Monitor Scanning", width=20, command=self.start_stop_monitor)
        self.btn_export_monitor = ttk.Button(self.monitor_button_frame, text="Export Monitor Log", width=20, command=lambda: self.export_log(self.log_monitor))
        self.btn_clear_monitor = ttk.Button(self.monitor_button_frame, text="Clear Monitor Log", width=20, command=lambda: self.clear_log(self.log_monitor, self.log_text_monitor))
        self.status_var_monitor = tk.StringVar()
        self.status_label_monitor = ttk.Label(self.monitor_button_frame, textvariable=self.status_var_monitor, font=('Helvetica', 12))
        
        # Webcam log frame
        self.log_frame_webcam = ttk.Frame(self.webcam_frame)
        self.log_label_webcam = ttk.Label(self.log_frame_webcam, text="Webcam Scan Log:", font=('Helvetica', 14, 'bold'))
        self.log_text_webcam = tk.Text(self.log_frame_webcam, height=10, width=50, wrap=tk.WORD, bg='#34495E', fg='#ECF0F1', font=('Helvetica', 12))
        self.log_text_webcam.config(state=tk.DISABLED)
        self.scrollbar_webcam = ttk.Scrollbar(self.log_frame_webcam, orient="vertical", command=self.log_text_webcam.yview)
        self.log_text_webcam.configure(yscrollcommand=self.scrollbar_webcam.set)
        
        # Monitor log frame
        self.log_frame_monitor = ttk.Frame(self.monitor_frame)
        self.log_label_monitor = ttk.Label(self.log_frame_monitor, text="Monitor Scan Log:", font=('Helvetica', 14, 'bold'))
        self.log_text_monitor = tk.Text(self.log_frame_monitor, height=10, width=50, wrap=tk.WORD, bg='#34495E', fg='#ECF0F1', font=('Helvetica', 12))
        self.log_text_monitor.config(state=tk.DISABLED)
        self.scrollbar_monitor = ttk.Scrollbar(self.log_frame_monitor, orient="vertical", command=self.log_text_monitor.yview)
        self.log_text_monitor.configure(yscrollcommand=self.scrollbar_monitor.set)

    def create_layout(self):
        self.window.grid_rowconfigure(0, weight=1)
        self.window.grid_columnconfigure(0, weight=1)
        
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)
        
        self.header_label.grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky="ew")
        
        # Webcam layout
        self.webcam_frame.grid(row=1, column=0, sticky="nsew")
        self.webcam_frame.grid_rowconfigure(1, weight=1)
        self.webcam_frame.grid_columnconfigure(0, weight=1)
        
        self.webcam_canvas.grid(row=0, column=0, pady=(0, 20), sticky="nsew")
        
        self.webcam_button_frame.grid(row=1, column=0, pady=(0, 20), sticky="ew")
        self.webcam_button_frame.grid_columnconfigure(3, weight=1)
        
        self.btn_start_stop_webcam.grid(row=0, column=0, padx=5)
        self.btn_export_webcam.grid(row=0, column=1, padx=5)
        self.btn_clear_webcam.grid(row=0, column=2, padx=5)
        self.status_label_webcam.grid(row=0, column=3, padx=5, sticky="e")
        
        self.log_frame_webcam.grid(row=2, column=0, sticky="nsew")
        self.log_frame_webcam.grid_rowconfigure(1, weight=1)
        self.log_frame_webcam.grid_columnconfigure(0, weight=1)
        
        self.log_label_webcam.grid(row=0, column=0, sticky="w", pady=(0, 5))
        self.log_text_webcam.grid(row=1, column=0, sticky="nsew")
        self.scrollbar_webcam.grid(row=1, column=1, sticky="ns")
        
        # Monitor layout
        self.monitor_frame.grid(row=1, column=1, sticky="nsew")
        self.monitor_frame.grid_rowconfigure(1, weight=1)
        self.monitor_frame.grid_columnconfigure(0, weight=1)
        
        self.monitor_canvas.grid(row=0, column=0, pady=(0, 20), sticky="nsew")
        
        self.monitor_button_frame.grid(row=1, column=0, pady=(0, 20), sticky="ew")
        self.monitor_button_frame.grid_columnconfigure(3, weight=1)
        
        self.btn_start_stop_monitor.grid(row=0, column=0, padx=5)
        self.btn_export_monitor.grid(row=0, column=1, padx=5)
        self.btn_clear_monitor.grid(row=0, column=2, padx=5)
        self.status_label_monitor.grid(row=0, column=3, padx=5, sticky="e")
        
        self.log_frame_monitor.grid(row=2, column=0, sticky="nsew")
        self.log_frame_monitor.grid_rowconfigure(1, weight=1)
        self.log_frame_monitor.grid_columnconfigure(0, weight=1)
        
        self.log_label_monitor.grid(row=0, column=0, sticky="w", pady=(0, 5))
        self.log_text_monitor.grid(row=1, column=0, sticky="nsew")
        self.scrollbar_monitor.grid(row=1, column=1, sticky="ns")

    def optimize_camera_settings(self):
        if self.vid:
            self.vid.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc('M', 'J', 'P', 'G'))
            self.vid.set(cv2.CAP_PROP_FPS, 30)
            self.vid.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
            self.vid.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)

    def start_stop_webcam(self):
        if self.is_scanning_webcam:
            self.stop_scanning_webcam()
        else:
            self.start_scanning_webcam()

    def start_stop_monitor(self):
        if self.is_scanning_monitor:
            self.stop_scanning_monitor()
        else:
            self.start_scanning_monitor()

    def start_scanning_webcam(self):
        logging.info("Attempting to start webcam scanning")
        if self.vid is None:
            try:
                self.vid = cv2.VideoCapture(0)
                if not self.vid.isOpened():
                    raise Exception("Unable to open camera")
                self.optimize_camera_settings()  # Add this line
                logging.info("Camera opened successfully")
            except Exception as e:
                logging.error(f"Error opening camera: {str(e)}")
                self.show_error("Camera Error", f"Unable to open camera: {str(e)}")
                return
        
        self.is_scanning_webcam = True
        self.btn_start_stop_webcam.config(text="Stop Webcam Scanning")
        self.update_status_webcam("Webcam scanning in progress...")
        threading.Thread(target=self.scan_qr_webcam, daemon=True).start()
        logging.info("Webcam scanning started successfully")

    def start_scanning_monitor(self):
        logging.info("Attempting to start monitor scanning")
        self.is_scanning_monitor = True
        self.btn_start_stop_monitor.config(text="Stop Monitor Scanning")
        self.update_status_monitor("Monitor scanning in progress...")
        threading.Thread(target=self.scan_qr_monitor, daemon=True).start()
        logging.info("Monitor scanning started successfully")

    def stop_scanning_webcam(self):
        logging.info("Stopping webcam scanning")
        self.is_scanning_webcam = False
        self.btn_start_stop_webcam.config(text="Start Webcam Scanning")
        self.update_status_webcam("Webcam scanning stopped")
        if self.vid:
            self.vid.release()
            self.vid = None
        logging.info("Webcam scanning stopped")

    def stop_scanning_monitor(self):
        logging.info("Stopping monitor scanning")
        self.is_scanning_monitor = False
        self.btn_start_stop_monitor.config(text="Start Monitor Scanning")
        self.update_status_monitor("Monitor scanning stopped")
        logging.info("Monitor scanning stopped")

    def scan_qr_webcam(self):
        logging.info("Webcam QR scanning thread started")
        while self.is_scanning_webcam:
            try:
                ret, frame = self.vid.read()
                if not ret:
                    logging.warning("Failed to grab frame from webcam")
                    continue
                
                # Convert to grayscale for faster processing
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

                # Adjust the resolution for QR code detection
                height, width = gray.shape
                min_side = min(height, width)
                scale_factor = 800 / min_side
                small_gray = cv2.resize(gray, (0, 0), fx=scale_factor, fy=scale_factor)

                # Increase contrast
                small_gray = cv2.equalizeHist(small_gray)

                # Apply Gaussian blur to reduce noise
                small_gray = cv2.GaussianBlur(small_gray, (5, 5), 0)

                # Try different thresholding methods
                _, binary = cv2.threshold(small_gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                
                # Detect QR codes
                barcodes = pyzbar.decode(binary)

                if not barcodes:
                    # If no QR codes found, try adaptive thresholding
                    adaptive_thresh = cv2.adaptiveThreshold(small_gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
                    barcodes = pyzbar.decode(adaptive_thresh)

                for barcode in barcodes:
                    barcode_data = barcode.data.decode("utf-8")
                    current_time = time.time()

                    if barcode_data != self.last_code_webcam and (current_time - self.last_time_webcam) >= 0.1:
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        log_entry = f"{timestamp}: {barcode_data}"
                        self.log_webcam.append(log_entry)
                        self.window.after(0, self.update_log, log_entry, "webcam")
                        logging.info(f"New QR code scanned from webcam: {barcode_data}")

                        self.last_code_webcam = barcode_data
                        self.last_time_webcam = current_time

                    # Draw bounding box (scale back to original size)
                    (x, y, w, h) = barcode.rect
                    cv2.rectangle(frame, 
                                  (int(x/scale_factor), int(y/scale_factor)), 
                                  (int((x+w)/scale_factor), int((y+h)/scale_factor)), 
                                  (0, 255, 0), 2)

                if self.frame_queue_webcam.full():
                    self.frame_queue_webcam.get_nowait()
                self.frame_queue_webcam.put(frame)
            except Exception as e:
                logging.error(f"Error in scan_qr_webcam: {str(e)}")
                self.window.after(0, self.show_error, "Webcam Scanning Error", str(e))
            
            time.sleep(0.01)  # Small delay to prevent excessive CPU usage

    def scan_qr_monitor(self):
        logging.info("Monitor QR scanning thread started")
        while self.is_scanning_monitor:
            try:
                screenshot = ImageGrab.grab()
                frame = cv2.cvtColor(np.array(screenshot), cv2.COLOR_RGB2GRAY)

                # Use a smaller resolution for faster processing
                small_frame = cv2.resize(frame, (0, 0), fx=0.5, fy=0.5)

                barcodes = pyzbar.decode(small_frame)

                for barcode in barcodes:
                    barcode_data = barcode.data.decode("utf-8")
                    current_time = time.time()

                    if barcode_data != self.last_code_monitor and (current_time - self.last_time_monitor) >= 0.1:
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                        log_entry = f"{timestamp}: {barcode_data}"
                        self.log_monitor.append(log_entry)
                        self.window.after(0, self.update_log, log_entry, "monitor")
                        logging.info(f"New QR code scanned from monitor: {barcode_data}")

                        self.last_code_monitor = barcode_data
                        self.last_time_monitor = current_time

                    # Draw bounding box (scale back to original size)
                    (x, y, w, h) = barcode.rect
                    cv2.rectangle(frame, (x*2, y*2), (x*2 + w*2, y*2 + h*2), (0, 255, 0), 2)

                if self.frame_queue_monitor.full():
                    self.frame_queue_monitor.get_nowait()
                self.frame_queue_monitor.put(cv2.cvtColor(frame, cv2.COLOR_GRAY2BGR))
            except Exception as e:
                logging.error(f"Error in scan_qr_monitor: {str(e)}")
                self.window.after(0, self.show_error, "Monitor Scanning Error", str(e))
            time.sleep(0.005)  # Reduced delay to increase scanning frequency

    def process_frame(self, frame, frame_queue, last_code, last_time, log, source):
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        barcodes = pyzbar.decode(gray)
        
        for barcode in barcodes:
            barcode_data = barcode.data.decode("utf-8")
            current_time = time.time()
            
            if barcode_data != last_code and (current_time - last_time) >= 0.1:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                log_entry = f"{timestamp}: {barcode_data}"
                log.append(log_entry)
                self.window.after(0, self.update_log, log_entry, source)
                logging.info(f"New QR code scanned from {source}: {barcode_data}")
                
                if source == "webcam":
                    self.last_code_webcam = barcode_data
                    self.last_time_webcam = current_time
                else:
                    self.last_code_monitor = barcode_data
                    self.last_time_monitor = current_time
            
            # Draw bounding box
            (x, y, w, h) = barcode.rect
            cv2.rectangle(frame, (x, y), (x + w, y + h), (0, 255, 0), 2)
        
        if frame_queue.full():
            frame_queue.get_nowait()
        frame_queue.put(frame)

    def update(self):
        self.update_canvas(self.frame_queue_webcam, self.webcam_canvas)
        self.update_canvas(self.frame_queue_monitor, self.monitor_canvas)
        self.window.after(self.delay, self.update)

    def update_canvas(self, frame_queue, canvas):
        try:
            frame = frame_queue.get_nowait()
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            
            # Resize frame to fit canvas while maintaining aspect ratio
            canvas_ratio = canvas.winfo_width() / canvas.winfo_height()
            frame_ratio = frame.shape[1] / frame.shape[0]
            
            if frame_ratio > canvas_ratio:
                new_width = canvas.winfo_width()
                new_height = int(new_width / frame_ratio)
            else:
                new_height = canvas.winfo_height()
                new_width = int(new_height * frame_ratio)
            
            frame = cv2.resize(frame, (new_width, new_height))
            
            photo = ImageTk.PhotoImage(image=Image.fromarray(frame))
            
            # Center the image on the canvas
            x_center = (canvas.winfo_width() - new_width) // 2
            y_center = (canvas.winfo_height() - new_height) // 2
            
            canvas.delete("all")
            canvas.create_image(x_center, y_center, image=photo, anchor=tk.NW)
            canvas.image = photo  # Keep a reference to prevent garbage collection
        except queue.Empty:
            pass
        except Exception as e:
            logging.error(f"Error in update_canvas: {str(e)}")

    def update_log(self, log_entry, source):
        try:
            if source == "webcam":
                log_text = self.log_text_webcam
            else:
                log_text = self.log_text_monitor
            
            log_text.config(state=tk.NORMAL)
            log_text.insert(tk.END, log_entry + "\n")
            log_text.see(tk.END)
            log_text.config(state=tk.DISABLED)
            logging.debug(f"Log updated for {source}: {log_entry}")
        except Exception as e:
            logging.error(f"Error updating log for {source}: {str(e)}")

    def export_log(self, log):
        if not log:
            messagebox.showinfo("Info", "No log entries to export.")
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, "w") as file:
                    for entry in log:
                        file.write(entry + "\n")
                messagebox.showinfo("Success", f"Log exported to {file_path}")
                logging.info(f"Log exported to {file_path}")
            except Exception as e:
                logging.error(f"Failed to export log: {str(e)}")
                self.show_error("Export Error", f"Failed to export log: {str(e)}")

    def clear_log(self, log, log_text):
        try:
            log.clear()
            log_text.config(state=tk.NORMAL)
            log_text.delete(1.0, tk.END)
            log_text.config(state=tk.DISABLED)
            logging.info("Log cleared")
        except Exception as e:
            logging.error(f"Error clearing log: {str(e)}")
            self.show_error("Clear Log Error", str(e))

    def update_status_webcam(self, message):
        self.status_var_webcam.set(f"Webcam Status: {message}")
        logging.info(f"Webcam status updated: {message}")

    def update_status_monitor(self, message):
        self.status_var_monitor.set(f"Monitor Status: {message}")
        logging.info(f"Monitor status updated: {message}")

    def show_error(self, title, message):
        logging.error(f"{title}: {message}")
        messagebox.showerror(title, message)

    def on_closing(self):
        try:
            if self.is_scanning_webcam:
                self.stop_scanning_webcam()
            if self.is_scanning_monitor:
                self.stop_scanning_monitor()
            self.window.destroy()
            logging.info("Application closed")
        except Exception as e:
            logging.error(f"Error during application closure: {str(e)}")

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = ModernQRScanner(root, "Modern macOS QR-Code Scanner")
        root.mainloop()
    except Exception as e:
        logging.critical(f"Critical error in main application: {str(e)}")
        messagebox.showerror("Critical Error", f"Application failed to start: {str(e)}")