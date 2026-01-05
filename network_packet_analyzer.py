import threading
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import tkinter as tk
from tkinter import ttk


sniffing = False
packet_count = 0
sniffer_thread = None


def packet_handler(packet):
    global packet_count

    if not sniffing:
        return

    if IP in packet:
        packet_count += 1

        time_now = datetime.now().strftime("%H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        else:
            protocol = "Other"

        root.after(0, update_gui,
                   packet_count, time_now, src_ip, dst_ip, protocol)


def update_gui(no, time, src, dst, proto):
    packet_table.insert("", "end", values=(no, time, src, dst, proto))
    counter_label.config(text=f"Packets Captured: {no}")


def stop_filter(packet):
    return not sniffing


def start_sniffer():
    sniff(prn=packet_handler,
          store=False,
          stop_filter=stop_filter,
          filter="ip")


def start_sniffing():
    global sniffing, sniffer_thread

    if sniffing:
        return  

    sniffing = True
    status_label.config(text="Sniffing Active", fg="green")

    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()

def stop_sniffing():
    global sniffing
    sniffing = False
    status_label.config(text="Sniffing Stopped", fg="red")


root = tk.Tk()
root.title("Network Packet Analyzer")
root.geometry("900x480")
root.configure(bg="#0f172a")

tk.Label(
    root,
    text="Network Packet Analyzer",
    font=("Segoe UI", 18, "bold"),
    bg="#0f172a",
    fg="white"
).pack(pady=10)

tk.Label(
    root,
    text="Developed by: Sriman Kundu | Educational Use Only",
    font=("Segoe UI", 9),
    bg="#0f172a",
    fg="gray"
).pack()

btn_frame = tk.Frame(root, bg="#0f172a")
btn_frame.pack(pady=10)

tk.Button(
    btn_frame, text="Start Sniffing",
    bg="green", fg="white",
    width=15, command=start_sniffing
).pack(side="left", padx=10)

tk.Button(
    btn_frame, text="Stop Sniffing",
    bg="red", fg="white",
    width=15, command=stop_sniffing
).pack(side="left", padx=10)

counter_label = tk.Label(
    root, text="Packets Captured: 0",
    bg="#0f172a", fg="cyan"
)
counter_label.pack()

status_label = tk.Label(
    root, text="Sniffing Stopped",
    bg="#0f172a", fg="red"
)
status_label.pack(pady=5)

columns = ("No", "Time", "Source IP", "Destination IP", "Protocol")
packet_table = ttk.Treeview(root, columns=columns, show="headings", height=12)

for col in columns:
    packet_table.heading(col, text=col)
    packet_table.column(col, width=160)

packet_table.pack(pady=10)


root.mainloop()
