# gui.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import sniffer
import scapy.all as scapy

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Packet Sniffer")
        self.root.geometry("1000x500")

        self.create_widgets()
        sniffer.register_callback(self.gui_add_packet)

    def create_widgets(self):
        self.packet_tree = ttk.Treeview(self.root, columns=("Source", "Destination", "Protocol", "Info"), show="headings")
        for col in ("Source", "Destination", "Protocol", "Info"):
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=200)
        self.packet_tree.pack(fill=tk.BOTH, expand=True)
        self.packet_tree.bind("<Double-1>", self.show_packet_details)

        control_frame = tk.Frame(self.root)
        control_frame.pack(fill=tk.X, pady=5)

        self.ip_entry = tk.Entry(control_frame)
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        self.ip_entry.insert(0, "Filter IP")

        self.proto_entry = tk.Entry(control_frame)
        self.proto_entry.pack(side=tk.LEFT, padx=5)
        self.proto_entry.insert(0, "Protocol (TCP/UDP)")

        tk.Button(control_frame, text="Apply Filters", command=self.apply_filters).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Start Sniffing", command=self.start_sniffing).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Save Packets", command=self.save_packets).pack(side=tk.LEFT, padx=5)

    def gui_add_packet(self, src, dst, proto, summary):
        self.packet_tree.insert("", "end", values=(src, dst, proto, summary))

    def apply_filters(self):
        ip = self.ip_entry.get().strip() or None
        proto_str = self.proto_entry.get().strip().upper()
        proto = scapy.TCP if proto_str == "TCP" else scapy.UDP if proto_str == "UDP" else None
        sniffer.set_filters(ip, proto)
        messagebox.showinfo("Filters Applied", "Filters updated.")

    def start_sniffing(self):
        threading.Thread(target=sniffer.start_sniffing, daemon=True).start()

    def save_packets(self):
        filepath = filedialog.asksaveasfilename(defaultextension=".txt",
                                                filetypes=[("Text Files", "*.txt"), ("PCAP Files", "*.pcap")])
        if filepath:
            sniffer.save_packets(filepath)
            messagebox.showinfo("Saved", f"Packets saved to {filepath}")

    def show_packet_details(self, event):
        selected_item = self.packet_tree.selection()
        if selected_item:
            index = self.packet_tree.index(selected_item)
            packet = sniffer.get_packet(index)
            if packet:
                packet.show()
