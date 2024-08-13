import tkinter as tk
from tkinter import ttk, filedialog
from ttkthemes import ThemedTk
from scapy.all import sniff, IP, TCP, UDP, ICMP
from threading import Thread, Event

# Initialize global variables
packet_count = 0
protocol_filter = None
stop_event = Event()
packet_data = []
last_number = 0


# Create the main window for packet capture
def create_main_window():
    global root, packet_listbox, status_var, protocol_var, protocol_filter_menu

    root = ThemedTk(theme="arc")
    root.title("Packet Sniffer Tool")
    root.geometry("800x600")

    # Create a Text widget to display captured packets
    packet_listbox = tk.Text(root, height=25, width=100, font=("Consolas", 10), bg="#2b2b2b", fg="#ffffff")
    packet_listbox.pack(pady=10)

    # Create a frame for the buttons and filter
    button_frame = ttk.Frame(root)
    button_frame.pack(pady=10)

    # Create protocol filter dropdown
    protocol_var = tk.StringVar(value="None")
    protocol_filter_menu = ttk.Combobox(button_frame, textvariable=protocol_var, values=["None", "TCP", "UDP", "ICMP"],
                                        state="readonly")
    protocol_filter_menu.bind("<<ComboboxSelected>>", update_filter)
    protocol_filter_menu.grid(row=0, column=0, padx=10)

    # Create Start, Stop, and Save buttons
    start_button = ttk.Button(button_frame, text="Start Sniffing", command=start_sniffing)
    start_button.grid(row=0, column=1, padx=10)

    stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing)
    stop_button.grid(row=0, column=2, padx=10)

    save_button = ttk.Button(button_frame, text="Save to File", command=save_to_file)
    save_button.grid(row=0, column=3, padx=10)

    # Create status bar
    status_var = tk.StringVar(value="Packets Captured: 0 | Filter Applied: None")
    status_bar = ttk.Label(root, textvariable=status_var, anchor='w', relief='sunken', padding=5)
    status_bar.pack(side='bottom', fill='x')

    # Create the table window
    create_table_window()

    # Run the GUI loop
    root.mainloop()


# Create the secondary window for table view
def create_table_window():
    global table_window, tree

    table_window = tk.Toplevel(root)
    table_window.title("Packet Data Table")
    table_window.geometry("700x400")

    # Create Treeview widget with an additional column for numbering
    tree = ttk.Treeview(table_window, columns=("No", "Source", "Destination", "Protocol", "Payload"), show='headings')
    tree.heading("No", text="No")
    tree.heading("Source", text="Source")
    tree.heading("Destination", text="Destination")
    tree.heading("Protocol", text="Protocol")
    tree.heading("Payload", text="Payload")

    # Set column widths
    tree.column("No", width=50, anchor='center')
    tree.column("Source", width=150, anchor='w')
    tree.column("Destination", width=150, anchor='w')
    tree.column("Protocol", width=100, anchor='w')
    tree.column("Payload", width=300, anchor='w')

    tree.pack(fill=tk.BOTH, expand=True)

    # Create Scrollbars
    vsb = ttk.Scrollbar(table_window, orient="vertical", command=tree.yview)
    vsb.pack(side='right', fill='y')
    tree.configure(yscrollcommand=vsb.set)

    hsb = ttk.Scrollbar(table_window, orient="horizontal", command=tree.xview)
    hsb.pack(side='bottom', fill='x')
    tree.configure(xscrollcommand=hsb.set)

    # Start updating the table
    root.after(1000, update_table_window)


def packet_callback(packet):
    global packet_count, last_number
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        protocol = "Other"
        src_port, dst_port = "N/A", "N/A"

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        if protocol_filter in [None, protocol]:
            last_number += 1
            packet_info = (
                last_number,  # Numbering column
                f"{ip_layer.src}:{src_port}",
                f"{ip_layer.dst}:{dst_port}",
                protocol,
                str(bytes(packet[IP].payload))
            )

            # Use `root.after()` to safely update the GUI from another thread
            root.after(0, update_packet_listbox, packet_info)
            packet_count += 1
            root.after(0, update_status_bar)
            update_table_data(packet_info)


def update_packet_listbox(packet_info):
    packet_listbox.insert(tk.END, f"Source: {packet_info[1]} -> Destination: {packet_info[2]}\n"
                                  f"Protocol: {packet_info[3]}\n"
                                  f"Payload: {packet_info[4]}\n"
                          + "-" * 50)
    packet_listbox.yview(tk.END)  # Scroll to the latest packet


def update_status_bar():
    status_var.set(
        f"Packets Captured: {packet_count} | Filter Applied: {protocol_filter if protocol_filter else 'None'}")


def start_sniffing():
    global stop_event
    stop_event.clear()
    sniff_thread = Thread(target=sniff_packets, daemon=True)
    sniff_thread.start()


def sniff_packets():
    sniff(prn=packet_callback, stop_filter=lambda x: stop_event.is_set())


def stop_sniffing():
    global stop_event
    stop_event.set()


def update_filter(event):
    global protocol_filter
    protocol_filter = protocol_var.get()
    update_status_bar()


def save_to_file():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(packet_listbox.get(1.0, tk.END))


def update_table_window():
    global packet_data
    tree.delete(*tree.get_children())
    for packet in packet_data:
        tree.insert("", tk.END, values=packet)

    # Schedule the next update
    root.after(1000, update_table_window)  # Update every second


def update_table_data(packet_info):
    global packet_data
    packet_data.append(packet_info)
    if len(packet_data) > 100:  # Limit to the most recent 100 packets
        packet_data.pop(0)


# Create and run the main window
create_main_window()
