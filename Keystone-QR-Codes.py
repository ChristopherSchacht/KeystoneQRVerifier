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
import sys
import os
from typing import Dict, Any, List, Optional, Tuple
import cbor2
from pycardano import Address, PaymentVerificationKey
import hashlib
import json
import binascii

sys.path.insert(0, './py_protocol')
from ur.ur_decoder import URDecoder

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class ModernQRScanner:
    def __init__(self, window, window_title):
        self.window = window
        self.window.title(window_title)
        self.window.geometry("1800x1170")
        self.window.configure(bg='#2C3E50')
        
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
        self.log_decoded_webcam = []
        self.log_decoded_monitor = []
        self.frame_queue_webcam = queue.Queue(maxsize=1)
        self.frame_queue_monitor = queue.Queue(maxsize=1)
        
        self.ur_decoder_webcam = URDecoder()
        self.ur_decoder_monitor = URDecoder()
        
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
            
            self.style.map('TButton',
                background=[('active', '#34495E'), ('!disabled', '#3498DB')],
                foreground=[('!disabled', 'white')]
            )
            
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

        # Webcam decoded log frame
        self.log_frame_decoded_webcam = ttk.Frame(self.webcam_frame)
        self.log_label_decoded_webcam = ttk.Label(self.log_frame_decoded_webcam, text="Decoded Webcam QR Data:", font=('Helvetica', 14, 'bold'))
        self.log_text_decoded_webcam = tk.Text(self.log_frame_decoded_webcam, height=20, width=50, wrap=tk.WORD, bg='#34495E', fg='#ECF0F1', font=('Helvetica', 12))
        self.log_text_decoded_webcam.config(state=tk.DISABLED)
        self.scrollbar_decoded_webcam = ttk.Scrollbar(self.log_frame_decoded_webcam, orient="vertical", command=self.log_text_decoded_webcam.yview)
        self.log_text_decoded_webcam.configure(yscrollcommand=self.scrollbar_decoded_webcam.set)

        # Monitor decoded log frame
        self.log_frame_decoded_monitor = ttk.Frame(self.monitor_frame)
        self.log_label_decoded_monitor = ttk.Label(self.log_frame_decoded_monitor, text="Decoded Monitor QR Data:", font=('Helvetica', 14, 'bold'))
        self.log_text_decoded_monitor = tk.Text(self.log_frame_decoded_monitor, height=20, width=50, wrap=tk.WORD, bg='#34495E', fg='#ECF0F1', font=('Helvetica', 12))
        self.log_text_decoded_monitor.config(state=tk.DISABLED)
        self.scrollbar_decoded_monitor = ttk.Scrollbar(self.log_frame_decoded_monitor, orient="vertical", command=self.log_text_decoded_monitor.yview)
        self.log_text_decoded_monitor.configure(yscrollcommand=self.scrollbar_decoded_monitor.set)

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

        self.log_frame_decoded_webcam.grid(row=3, column=0, sticky="nsew", pady=(20, 0))
        self.log_frame_decoded_webcam.grid_rowconfigure(1, weight=1)
        self.log_frame_decoded_webcam.grid_columnconfigure(0, weight=1)
        
        self.log_label_decoded_webcam.grid(row=0, column=0, sticky="w", pady=(0, 5))
        self.log_text_decoded_webcam.grid(row=1, column=0, sticky="nsew")
        self.scrollbar_decoded_webcam.grid(row=1, column=1, sticky="ns")
        
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

        self.log_frame_decoded_monitor.grid(row=3, column=0, sticky="nsew", pady=(20, 0))
        self.log_frame_decoded_monitor.grid_rowconfigure(1, weight=1)
        self.log_frame_decoded_monitor.grid_columnconfigure(0, weight=1)
        
        self.log_label_decoded_monitor.grid(row=0, column=0, sticky="w", pady=(0, 5))
        self.log_text_decoded_monitor.grid(row=1, column=0, sticky="nsew")
        self.scrollbar_decoded_monitor.grid(row=1, column=1, sticky="ns")

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
                self.optimize_camera_settings()
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
                
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                height, width = gray.shape
                min_side = min(height, width)
                scale_factor = 800 / min_side
                small_gray = cv2.resize(gray, (0, 0), fx=scale_factor, fy=scale_factor)
                small_gray = cv2.equalizeHist(small_gray)
                small_gray = cv2.GaussianBlur(small_gray, (5, 5), 0)
                _, binary = cv2.threshold(small_gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                
                barcodes = pyzbar.decode(binary)

                if not barcodes:
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
            
            time.sleep(0.01)

    def scan_qr_monitor(self):
        logging.info("Monitor QR scanning thread started")
        while self.is_scanning_monitor:
            try:
                screenshot = ImageGrab.grab()
                frame = cv2.cvtColor(np.array(screenshot), cv2.COLOR_RGB2GRAY)
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

                    (x, y, w, h) = barcode.rect
                    cv2.rectangle(frame, (x*2, y*2), (x*2 + w*2, y*2 + h*2), (0, 255, 0), 2)

                if self.frame_queue_monitor.full():
                    self.frame_queue_monitor.get_nowait()
                self.frame_queue_monitor.put(cv2.cvtColor(frame, cv2.COLOR_GRAY2BGR))
            except Exception as e:
                logging.error(f"Error in scan_qr_monitor: {str(e)}")
                self.window.after(0, self.show_error, "Monitor Scanning Error", str(e))
            time.sleep(0.005)

    def decode_ur(self, content: List[str], source: str) -> Optional[Any]:
        decoder = self.ur_decoder_webcam if source == "webcam" else self.ur_decoder_monitor
        for part in content:
            decoder.receive_part(part.lower().strip())
        return decoder.result_message() if decoder.is_success() else None

    def decode_cardano_request(self, ur_content: Any) -> Dict[str, Any]:
        return {'type': ur_content.type, 'data': cbor2.loads(ur_content.cbor)}

    def decode_qr_data(self, qr_data: str, source: str) -> str:
        try:
            ur = self.decode_ur([qr_data], source)
            if ur is None:
                percent_complete = (self.ur_decoder_webcam if source == "webcam" else self.ur_decoder_monitor).estimated_percent_complete() * 100
                return f"Incomplete QR data ({percent_complete:.2f}% complete)"

            decoded_data = self.decode_cardano_request(ur)
            
            if ur.type == 'cardano-sign-request':
                return self.format_transaction_details(decoded_data['data'])
            elif ur.type == 'cardano-sign-data-request':
                return self.format_sign_data_details(decoded_data['data'])
            elif ur.type == 'cardano-sign-data-signature':
                return self.format_sign_data_signature_details(decoded_data['data'])
            elif ur.type == 'cardano-signature':
                return self.format_signature_details(decoded_data['data'])
            else:
                return f"Unsupported Cardano request type: {ur.type}\n\nRaw data: {decoded_data}"
        except Exception as e:
            logging.error(f"Error decoding QR data: {str(e)}")
            return f"Error decoding QR data: {str(e)}\n\nRaw QR data: {qr_data}"
        
    def format_sign_data_signature_details(self, data: Dict[int, Any]) -> str:
        result = []
        result.append(f"Type: Cardano Sign Data Signature")
        result.append(f"Request ID: {data.get(1, 'N/A')}")
        
        signature = data.get(2, b'')
        result.append(f"Signature: {signature.hex()}")
        
        public_key = data.get(3, b'')
        result.append(f"Public Key: {public_key.hex()}")
        
        witness = data.get(4, b'')
        if witness:
            result.append(f"Witness: {witness.hex()}")
        else:
            result.append("Witness: None")
        
        # Add any additional fields that might be present
        for key, value in data.items():
            if key not in {1, 2, 3, 4}:
                result.append(f"Additional Field ({key}): {value}")
        
        return "\n".join(result)

    def format_signature_details(self, data: Dict[int, Any]) -> str:
        result = []
        result.append(f"Type: Cardano Signature")
        result.append(f"Request ID: {data.get(1, 'N/A')}")

        signature = data.get(2, b'')
        result.append(f"Signature (hex): {signature.hex()}")

        key_path = data.get(3, b'')
        if isinstance(key_path, bytes):
            result.append(f"Key Path: {key_path.hex()}")
        elif isinstance(key_path, list):
            result.append(f"Key Path: {'/'.join(map(str, key_path))}")
        else:
            result.append(f"Key Path: {key_path}")

        witness = data.get(4, b'')
        if witness:
            result.append(f"Witness: {witness.hex()}")
        else:
            result.append("Witness: None")

        # Attempt to decode the signature
        try:
            decoded_signature = cbor2.loads(signature)
            result.append("\nDecoded Signature:")
            result.append(self.format_decoded_signature(decoded_signature))
        except Exception as e:
            result.append(f"Failed to decode signature: {e}")

        # Add any additional fields that might be present
        for key, value in data.items():
            if key not in {1, 2, 3, 4}:
                result.append(f"Additional Field ({key}): {self.format_value(value)}")

        return "\n".join(result)

    def format_decoded_signature(self, decoded_signature: Any, indent: str = "  ") -> str:
        if isinstance(decoded_signature, dict):
            return self.format_dict(decoded_signature, indent)
        elif isinstance(decoded_signature, list):
            return self.format_list(decoded_signature, indent)
        elif isinstance(decoded_signature, bytes):
            return f"{indent}Bytes: {decoded_signature.hex()}"
        else:
            return f"{indent}{decoded_signature}"

    def format_dict(self, d: Dict[Any, Any], indent: str = "  ") -> str:
        result = []
        for key, value in d.items():
            if key == 0:
                result.append(f"{indent}Signature Components:")
            else:
                result.append(f"{indent}Field {key}:")
            result.append(self.format_decoded_signature(value, indent + "  "))
        return "\n".join(result)

    def format_list(self, l: List[Any], indent: str = "  ") -> str:
        result = []
        for i, item in enumerate(l):
            if isinstance(item, list) and len(item) == 2 and all(isinstance(x, bytes) for x in item):
                result.append(f"{indent}Component {i+1}:")
                result.append(f"{indent}  Public Key: {item[0].hex()}")
                result.append(f"{indent}  Signature: {item[1].hex()}")
            else:
                result.append(f"{indent}Item {i+1}:")
                result.append(self.format_decoded_signature(item, indent + "  "))
        return "\n".join(result)

    def format_value(self, value: Any) -> str:
        if isinstance(value, bytes):
            return f"Bytes: {value.hex()}"
        elif isinstance(value, (list, dict)):
            return "\n" + self.format_decoded_signature(value)
        else:
            return str(value)

    def decode_cardano_request(self, ur_content: Any) -> Dict[str, Any]:
        decoded_data = {'type': ur_content.type, 'data': cbor2.loads(ur_content.cbor)}
        
        # Add more detailed decoding based on the type
        if ur_content.type == 'cardano-signature':
            decoded_data['detailed'] = self.decode_cardano_signature(decoded_data['data'])
        elif ur_content.type == 'cardano-sign-data-signature':
            decoded_data['detailed'] = self.decode_cardano_sign_data_signature(decoded_data['data'])
        
        return decoded_data

    def decode_cardano_signature(self, data: Dict[int, Any]) -> Dict[str, Any]:
        return {
            'request_id': data.get(1, 'N/A'),
            'signature': data.get(2, b'').hex(),
            'key_path': self.decode_key_path(data.get(3, b'')),
            'witness': data.get(4, b'').hex() if data.get(4) else None
        }

    def decode_cardano_sign_data_signature(self, data: Dict[int, Any]) -> Dict[str, Any]:
        return {
            'request_id': data.get(1, 'N/A'),
            'signature': data.get(2, b'').hex(),
            'public_key': data.get(3, b'').hex(),
            'witness': data.get(4, b'').hex() if data.get(4) else None
        }

    def decode_key_path(self, key_path: Any) -> str:
        if isinstance(key_path, bytes):
            return key_path.hex()
        elif isinstance(key_path, list):
            return '/'.join(map(str, key_path))
        else:
            return str(key_path)

    def format_transaction_details(self, data: Dict[int, Any]) -> str:
        result = []
        result.append(f"Request ID: {data.get(1, 'N/A')}")
        sign_data = data.get(2, b'')
        
        result.append("\nRaw Transaction Data:")
        result.append(sign_data.hex())
        
        try:
            decoded_sign_data = cbor2.loads(sign_data)
            result.append("\nDecoded Transaction Structure:")
            result.append(str(decoded_sign_data))
            
            tx_body = decoded_sign_data[0]
            result.append("\nTransaction Body Details:")
            
            # Inputs
            result.append("\nInputs:")
            for i, input_data in enumerate(tx_body.get(0, []), 1):
                result.append(f"  Input {i}:")
                result.append(f"    - TX Hash: {input_data[0].hex()}")
                result.append(f"    - Index: {input_data[1]}")
            
            # Outputs
            result.append("\nOutputs:")
            for i, output_data in enumerate(tx_body.get(1, []), 1):
                result.append(f"  Output {i}:")
                address, amount = output_data
                result.append(f"    - Address: {self.decode_address_data(address)}")
                result.append(f"    - Amount: {amount} lovelace ({amount/1000000:.6f} ADA)")
            
            # Fee
            fee = tx_body.get(2, 0)
            result.append(f"\nFee: {fee} lovelace ({fee/1000000:.6f} ADA)")
            
            # TTL
            result.append(f"TTL: {tx_body.get(3, 'N/A')}")
            
            # Additional fields
            for key, value in tx_body.items():
                if key not in {0, 1, 2, 3}:
                    result.append(f"Additional field ({key}): {value}")
            
            # Calculate totals
            total_output = sum(output[1] for output in tx_body.get(1, []))
            total_input = total_output + fee
            result.append(f"\nTotal Input: {total_input} lovelace ({total_input/1000000:.6f} ADA)")
            result.append(f"Total Output: {total_output} lovelace ({total_output/1000000:.6f} ADA)")
        
        except Exception as e:
            result.append(f"Failed to decode transaction body: {e}")
        
        result.append(f"\nOrigin: {data.get(5, 'N/A')}")
        return "\n".join(result)

    def format_sign_data_details(self, data: Dict[int, Any]) -> str:
        result = []
        result.append(f"Request ID: {data.get(1, 'N/A')}")
        
        payload = data.get(2, b'')
        signature_type, address_data, extracted_payload, message_hash = self.extract_payload_and_hash(payload)
        
        result.append(f"\nSignature Type: {signature_type}")
        result.append(f"\nAddress: {self.decode_address_data(address_data)}")
        result.append(f"\nPayload: {extracted_payload}")
        result.append(f"\nMessage Hash: {message_hash}")
        result.append(f"\nDerivation Path: {self.parse_derivation_path(data.get(3, 'N/A'))}")
        result.append(f"\nOrigin: {data.get(4, 'N/A')}")
        
        public_key = data.get(6, b'')
        result.append(f"\nPublic Key: {self.format_public_key(public_key)}")
        
        if isinstance(public_key, bytes):
            try:
                vk = PaymentVerificationKey.from_primitive(public_key)
                vk_dict = vk.to_json()
                result.append("\nDecoded Verification Key:")
                for key, value in vk_dict.items():
                    result.append(f"  {key.capitalize()}: {value}")
            except Exception as e:
                result.append(f"Failed to decode public key: {e}")
        
        return "\n".join(result)

    def decode_address_data(self, address_data: Any) -> str:
        try:
            decoded = cbor2.loads(address_data)
            if isinstance(decoded, dict) and 'address' in decoded:
                return Address.from_primitive(decoded['address']).encode()
            elif isinstance(address_data, bytes):
                return Address.from_primitive(address_data).encode()
        except Exception as e:
            logging.error(f"Failed to decode address data: {e}")
        return str(address_data)

    def extract_payload_and_hash(self, payload: bytes) -> Tuple[Any, Any, str, str]:
        try:
            data = cbor2.loads(payload)
            if isinstance(data, list) and len(data) == 4:
                signature_type, address_data, _, payload_content = data
                extracted_payload = payload_content.decode('utf-8', errors='replace') if isinstance(payload_content, bytes) else str(payload_content)
                message_hash = hashlib.sha256(payload).hexdigest()
                return signature_type, address_data, extracted_payload, message_hash
        except Exception as e:
            logging.error(f"Debug - Exception in extract_payload_and_hash: {e}")
        return None, None, None, None

    def parse_derivation_path(self, path_data: Any) -> str:
        if isinstance(path_data, cbor2.CBORTag) and path_data.tag == 304:
            path_dict = path_data.value
            if isinstance(path_dict, dict) and 1 in path_dict:
                path = path_dict[1]
                return '/'.join(f"{p}'" if hardened else str(p) for p, hardened in zip(path[::2], path[1::2]))
        elif isinstance(path_data, dict) and 1 in path_data:
            path = path_data[1]
            return '/'.join(f"{p}'" if hardened else str(p) for p, hardened in zip(path[::2], path[1::2]))
        return str(path_data)

    def format_public_key(self, key: Any) -> str:
        return key.hex() if isinstance(key, bytes) else str(key)
    
    def update(self):
        self.update_canvas(self.frame_queue_webcam, self.webcam_canvas)
        self.update_canvas(self.frame_queue_monitor, self.monitor_canvas)
        self.window.after(self.delay, self.update)


    def update_canvas(self, frame_queue, canvas):
        try:
            frame = frame_queue.get_nowait()
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            
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
            
            x_center = (canvas.winfo_width() - new_width) // 2
            y_center = (canvas.winfo_height() - new_height) // 2
            
            canvas.delete("all")
            canvas.create_image(x_center, y_center, image=photo, anchor=tk.NW)
            canvas.image = photo
        except queue.Empty:
            pass
        except Exception as e:
            logging.error(f"Error in update_canvas: {str(e)}")

    def update_log(self, log_entry, source):
        try:
            if source == "webcam":
                log_text = self.log_text_webcam
                decoded_log_text = self.log_text_decoded_webcam
            elif source == "monitor":
                log_text = self.log_text_monitor
                decoded_log_text = self.log_text_decoded_monitor
            else:
                return
            
            log_text.config(state=tk.NORMAL)
            log_text.insert(tk.END, log_entry + "\n")
            log_text.see(tk.END)
            log_text.config(state=tk.DISABLED)
            logging.debug(f"Log updated for {source}: {log_entry}")

            qr_data = log_entry.split(": ", 1)[1]
            decoded_data = self.decode_qr_data(qr_data, source)
            
            decoded_log_text.config(state=tk.NORMAL)
            decoded_log_text.insert(tk.END, f"Decoded data for {source}:\n{decoded_data}\n\n")
            decoded_log_text.see(tk.END)
            decoded_log_text.config(state=tk.DISABLED)
            logging.debug(f"Decoded log updated for {source}")

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
            
            if log_text == self.log_text_webcam:
                decoded_log_text = self.log_text_decoded_webcam
                self.ur_decoder_webcam = URDecoder()
            elif log_text == self.log_text_monitor:
                decoded_log_text = self.log_text_decoded_monitor
                self.ur_decoder_monitor = URDecoder()
            else:
                return

            decoded_log_text.config(state=tk.NORMAL)
            decoded_log_text.delete(1.0, tk.END)
            decoded_log_text.config(state=tk.DISABLED)

            logging.info(f"Log and decoded log cleared for {'webcam' if log_text == self.log_text_webcam else 'monitor'}")
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
        app = ModernQRScanner(root, "Modern macOS QR-Code Scanner with Decoding")
        root.mainloop()
    except Exception as e:
        logging.critical(f"Critical error in main application: {str(e)}")
        messagebox.showerror("Critical Error", f"Application failed to start: {str(e)}")