import scapy.all as scapy
import tkinter as tk
from tkinter import ttk
import threading
import subprocess

class NetworkTrafficMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Traffic Monitoring System")
        self.root.geometry("1270x335")

        self.ip_counter = {}
        self.suspicious_ips = set()
        self.blocked_ips = set()
        self.monitoring_active = False

        all_ips_frame = tk.Frame(root)
        all_ips_frame.grid(row=0, column=0, padx=10, pady=10, sticky="n")

        suspicious_ips_frame = tk.Frame(root)
        suspicious_ips_frame.grid(row=0, column=1, padx=10, pady=10, sticky="n")

        blocked_ips_frame = tk.Frame(root)
        blocked_ips_frame.grid(row=0, column=2, padx=10, pady=10, sticky="n")

        tk.Label(all_ips_frame, text="All Incoming IPs").pack(side="top")
        self.all_ips_table = ttk.Treeview(all_ips_frame, columns=("IP", "Port", "Size"), show="headings", height=10)
        self.all_ips_table.heading("IP", text="IP Address")
        self.all_ips_table.heading("Port", text="Port")
        self.all_ips_table.heading("Size", text="Size")
        self.all_ips_table.pack(side="top", fill="both", expand=True)

        self.start_button = tk.Button(all_ips_frame, text="Start", command=self.start_monitoring)
        self.start_button.pack(fill="x", padx=0, pady=5)

        self.stop_button = tk.Button(all_ips_frame, text="Stop", command=self.stop_monitoring)
        self.stop_button.pack(fill="x", padx=0, pady=0)

        tk.Label(suspicious_ips_frame, text="Suspicious IPs").pack(side="top")
        self.suspicious_ips_table = ttk.Treeview(suspicious_ips_frame, columns=("IP", "Reason"), show="headings", height=10)
        self.suspicious_ips_table.heading("IP", text="IP Address")
        self.suspicious_ips_table.heading("Reason", text="Reason")
        self.suspicious_ips_table.pack(side="top", fill="both", expand=True)

        self.block_button = tk.Button(suspicious_ips_frame, text="Block", command=self.block_ip)
        self.block_button.pack(fill="x", padx=0, pady=5)

        tk.Label(blocked_ips_frame, text="Blocked IPs").pack(side="top")
        self.blocked_ips_table = ttk.Treeview(blocked_ips_frame, columns=("IP",), show="headings", height=10)
        self.blocked_ips_table.heading("IP", text="IP Address")
        self.blocked_ips_table.pack(side="top", fill="both", expand=True)

        self.unblock_button = tk.Button(blocked_ips_frame, text="Unblock", command=self.unblock_ip)
        self.unblock_button.pack(fill="x", padx=0, pady=5)

    def packet_callback(self, packet):
        if packet.haslayer(scapy.IP):
            ip_address = packet[scapy.IP].src
            packet_size = len(packet)

            if ip_address not in self.ip_counter:
                self.ip_counter[ip_address] = 0

            self.ip_counter[ip_address] += packet_size

            if self.ip_counter[ip_address] > 200:
                if ip_address not in self.suspicious_ips:
                    self.suspicious_ips.add(ip_address)
                    self.suspicious_ips_table.insert("", "end", values=(ip_address, "Packet size exceeded"))

            if ip_address not in self.blocked_ips:
                self.all_ips_table.insert("", "end", values=(ip_address, packet[scapy.IP].sport, packet_size))

    def start_monitoring(self):
        self.suspicious_ips_table.delete(*self.suspicious_ips_table.get_children())
        self.all_ips_table.delete(*self.all_ips_table.get_children())

        self.monitoring_active = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        monitoring_thread = threading.Thread(target=self.monitor_traffic)
        monitoring_thread.daemon = True
        monitoring_thread.start()
        print("Monitoring started")

    def monitor_traffic(self):
        scapy.sniff(prn=self.packet_callback, store=0)

    def stop_monitoring(self):
        self.monitoring_active = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        print("Monitoring stopped")

    def block_ip(self):
        selected_item = self.suspicious_ips_table.selection()
        if selected_item:
            ip_address = self.suspicious_ips_table.item(selected_item[0])['values'][0]
            if ip_address not in self.blocked_ips:
                self.blocked_ips.add(ip_address)
                self.blocked_ips_table.insert("", "end", values=(ip_address,))
                self.add_iptables_rule(ip_address)
                self.suspicious_ips_table.delete(selected_item)

    def unblock_ip(self):
        selected_item = self.blocked_ips_table.selection()
        if selected_item:
            ip_address = self.blocked_ips_table.item(selected_item[0])['values'][0]
            if ip_address in self.blocked_ips:
                self.blocked_ips.remove(ip_address)
                self.remove_iptables_rule(ip_address)
                self.blocked_ips_table.delete(selected_item)

    def add_iptables_rule(self, ip_address):
        try:
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            print(f"IP address blocked with iptables: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error blocking IP address {ip_address}: {e}")

    def remove_iptables_rule(self, ip_address):
        try:
            subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            print(f"IP address unblocked with iptables: {ip_address}")
        except subprocess.CalledProcessError as e:
            print(f"Error unblocking IP address {ip_address}: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    monitor = NetworkTrafficMonitor(root)
    root.mainloop()
