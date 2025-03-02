import tkinter as tk
from tkinter import ttk, messagebox
import threading
import queue
import time
import psutil
import requests
import http.server
import socketserver
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Global counter for active requests and request tracking
active_requests = 0
lock = threading.Lock()
request_counts = defaultdict(int)  # Track requests per IP
THRESHOLD = 5  # Requests per IP within TIME_WINDOW to trigger block
TIME_WINDOW = 10  # Time window in seconds

# Proxy Server Handler
class ProxyHandler(http.server.BaseHTTPRequestHandler):
    blocked_ips = set()
    log_queue = queue.Queue()

    def do_POST(self):
        global active_requests, request_counts
        client_ip = self.client_address[0]

        # Check if IP is blocked
        if client_ip in ProxyHandler.blocked_ips:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Access Denied")
            ProxyHandler.log_queue.put((client_ip, "Blocked"))
            return

        # Track request count for rate limiting
        request_counts[client_ip] += 1

        if request_counts[client_ip] > THRESHOLD:
            ProxyHandler.block_ip(client_ip)
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Blocked due to flooding")
            ProxyHandler.log_queue.put((client_ip, "Blocked due to flooding"))
            return

        # Increase active requests count
        with lock:
            active_requests += 1

        ProxyHandler.log_queue.put((client_ip, "Active"))

        time.sleep(1)  # Simulating processing delay

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{\"message\": \"Request received successfully\"}")

        # Decrease active requests count
        with lock:
            active_requests -= 1

        ProxyHandler.log_queue.put((client_ip, "Completed"))

    @classmethod
    def block_ip(cls, ip):
        cls.blocked_ips.add(ip)
        print(f"Blocked IP: {ip} due to flooding")

    @classmethod
    def unblock_ip(cls, ip):
        if ip in cls.blocked_ips:
            cls.blocked_ips.discard(ip)
            request_counts[ip] = 0  # Reset request count to allow new requests
            print(f"Unblocked IP: {ip}")

# Start the Proxy Server
def start_proxy_server():
    with socketserver.ThreadingTCPServer(('127.0.0.1', 5001), ProxyHandler) as server:
        print("Proxy Server Running on port 5001...")
        server.serve_forever()

# Initialize Tkinter app
class ShamashShieldApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ShamashShield")
        self.root.geometry("1000x600")
        self.root.configure(bg="white")

        self.create_widgets()
        self.queue = queue.Queue()

        self.monitoring_thread = threading.Thread(target=self.monitor_resources, daemon=True)
        self.monitoring_thread.start()

        self.proxy_thread = threading.Thread(target=start_proxy_server, daemon=True)
        self.proxy_thread.start()

        self.root.after(1000, self.process_queue)

    def create_widgets(self):
        # Main Frame
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill='both', expand=True)

        # Logs Section (Left Side)
        log_frame = ttk.Frame(main_frame, padding=10)
        log_frame.pack(side='left', fill='both', expand=True)

        # Dashboard Section (Right Side)
        dashboard_frame = ttk.Frame(main_frame, padding=10)
        dashboard_frame.pack(side='right', fill='both', expand=True)

        title_label = ttk.Label(dashboard_frame, text="ShamashShield", font=("Arial", 18, "bold"), background="white")
        title_label.pack(pady=2)

        stats_frame = ttk.Frame(dashboard_frame, padding=10)
        stats_frame.pack(pady=5)

        self.cpu_label = ttk.Label(stats_frame, text="CPU USAGE: 0%", font=("Arial", 12, "bold"), background="white")
        self.cpu_label.grid(row=0, column=0, padx=10)

        self.memory_label = ttk.Label(stats_frame, text="Memory Usage: 0%", font=("Arial", 12, "bold"), background="white")
        self.memory_label.grid(row=0, column=1, padx=10)

        self.requests_label = ttk.Label(stats_frame, text="Active request: 0", font=("Arial", 12, "bold"), background="white")
        self.requests_label.grid(row=0, column=2, padx=10)

        self.block_ip_entry = ttk.Entry(dashboard_frame, font=("Arial", 12))
        self.block_ip_entry.pack(pady=5)

        self.block_button = ttk.Button(dashboard_frame, text="Block IP", command=self.manual_block_ip)
        self.block_button.pack(pady=5)

        self.unblock_button = ttk.Button(dashboard_frame, text="Unblock IP", command=self.manual_unblock_ip)
        self.unblock_button.pack(pady=5)

        self.log_tree = ttk.Treeview(log_frame, columns=("IP Address", "Status"), show="headings", height=15)
        self.log_tree.heading("IP Address", text="IP Address")
        self.log_tree.heading("Status", text="Status")
        self.log_tree.pack(pady=5, padx=10, fill="both", expand=True)

    def monitor_resources(self):
        while True:
            global active_requests
            cpu_usage = psutil.cpu_percent()
            memory_usage = psutil.virtual_memory().percent

            with lock:
                current_requests = active_requests

            self.queue.put(("cpu", cpu_usage))
            self.queue.put(("memory", memory_usage))
            self.queue.put(("requests", current_requests))

            while not ProxyHandler.log_queue.empty():
                log_entry = ProxyHandler.log_queue.get()
                self.queue.put(("log", log_entry))

            time.sleep(1)

    def process_queue(self):
        while not self.queue.empty():
            event, value = self.queue.get()
            if event == "cpu":
                self.cpu_label.config(text=f"CPU USAGE: {value}%")
            elif event == "memory":
                self.memory_label.config(text=f"Memory Usage: {value}%")
            elif event == "requests":
                self.requests_label.config(text=f"Active request: {value}")
            elif event == "log":
                self.log_tree.insert("", "end", values=value)

        self.root.after(1000, self.process_queue)

    def manual_block_ip(self):
        ip = self.block_ip_entry.get()
        if ip:
            ProxyHandler.block_ip(ip)
            self.block_ip_entry.delete(0, tk.END)
            self.log_tree.insert("", "end", values=(ip, "Manually Blocked"))

    def manual_unblock_ip(self):
        selected = self.log_tree.selection()
        for item in selected:
            ip = self.log_tree.item(item, "values")[0]
            ProxyHandler.unblock_ip(ip)
            self.log_tree.delete(item)

if __name__ == "__main__":
    root = tk.Tk()
    app = ShamashShieldApp(root)
    root.mainloop()
