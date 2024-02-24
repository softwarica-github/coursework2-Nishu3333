import platform
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
from queue import Queue
from scapy.all import sniff, Ether, ARP, IP, TCP, UDP
from datetime import datetime

class NetworkSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer")
        self.root.geometry("800x600")
        self.root.configure(bg="#2c3e50")  # Set background color to dark blue

        self.interface_var = tk.StringVar()
        self.interface_var.set(self.get_default_interface())

        self.create_widgets()

        # Queue for communication between threads
        self.packet_queue = Queue()

        # Display welcome message
        self.display_welcome_message()

    def display_welcome_message(self):
        welcome_message = "Welcome to the Network Sniffing Tool!"
        welcome_label = ttk.Label(self.root, text=welcome_message, font=("Helvetica", 16), foreground="#3498db", background="#2c3e50")
        welcome_label.grid(row=0, column=0, columnspan=5, pady=20, sticky=tk.W+tk.E)

    def create_widgets(self):
        # Interface selection
        interface_label = ttk.Label(self.root, text="Select Interface:", foreground="#ecf0f1", background="#2c3e50")  # Light blue text on dark blue background
        interface_combobox = ttk.Combobox(self.root, textvariable=self.interface_var, values=self.get_interfaces())
        interface_combobox.bind("<Button-1>", lambda event: self.update_interfaces())

        # Start/Stop button
        start_button = ttk.Button(self.root, text="Start Sniffing", command=self.start_sniffing)

        # Save Packets button
        save_button = ttk.Button(self.root, text="Save Packets", command=self.save_packets)

        # Exit button
        exit_button = ttk.Button(self.root, text="Exit", command=self.root.destroy)

        # Packet display area
        self.packet_display = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, width=80, height=20, foreground="#2c3e50", background="#ecf0f1")  # Dark blue text on light blue background
        self.packet_display.config(state=tk.DISABLED)

        # Grid layout
        interface_label.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        interface_combobox.grid(row=1, column=1, padx=10, pady=10, sticky=tk.W)
        start_button.grid(row=1, column=2, padx=10, pady=10, sticky=tk.W)
        save_button.grid(row=1, column=3, padx=10, pady=10, sticky=tk.W)
        exit_button.grid(row=1, column=4, padx=10, pady=10, sticky=tk.W)
        self.packet_display.grid(row=2, column=0, columnspan=5, padx=10, pady=10, sticky=tk.W+tk.E+tk.N+tk.S)

    def save_packets(self):
        # Save the captured packets to a file with timestamps
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "a") as file:  # Open in append mode
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                file.write(f"\n\nPackets captured on {current_time}:\n")
                
                # Use a loop to get packets from the queue
                while not self.packet_queue.empty():
                    packet = self.packet_queue.get()
                    file.write(packet)

            # Display a message after saving
            messagebox.showinfo("Save Packets", "Packets saved successfully!")

    def get_default_interface(self):
        if platform.system() == "Windows":
            return "Wi-Fi"  # Change this based on your Windows interface name
        else:
            return "wlan0"  # Change this based on your Linux interface name

    def get_interfaces(self):
        return ["eth0", "eth1"]  # Add more interfaces as needed

    def update_interfaces(self):
        # Update the list of interfaces when the dropdown is clicked
        interfaces = self.get_interfaces()
        self.interface_var.set(interfaces[0])
        self.root.children["!combobox"].configure(values=interfaces)

    def start_sniffing(self):
        self.packet_display.config(state=tk.NORMAL)
        self.packet_display.delete(1.0, tk.END)
        self.packet_display.insert(tk.END, "Sniffing started on interface: {}\n".format(self.interface_var.get()))
        self.packet_display.config(state=tk.DISABLED)

        # Sniff packets in a separate thread
        sniff_thread = threading.Thread(target=self.sniff_packets)
        sniff_thread.start()

        return sniff_thread #return the thread instance 

    def sniff_packets(self):
        sniff(prn=self.packet_callback, store=0, iface=self.interface_var.get())

    def packet_callback(self, packet):
        if Ether in packet:
            dest_mac = packet[Ether].dst
            src_mac = packet[Ether].src
            eth_type = packet[Ether].type

            output = f'\nEthernet Frame:\nDestination: {dest_mac}, Source: {src_mac}, EtherType: {hex(eth_type)}\n'

            if IP in packet:
                src_ip = packet[IP].src
                dest_ip = packet[IP].dst
                protocol = packet[IP].proto

                output += f'IP Packet:\nSource IP: {src_ip}, Destination IP: {dest_ip}, Protocol: {protocol}\n'

                if TCP in packet:
                    src_port = packet[TCP].sport
                    dest_port = packet[TCP].dport
                    output += f'TCP Segment:\nSource Port: {src_port}, Destination Port: {dest_port}\n'

                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dest_port = packet[UDP].dport
                    output += f'UDP Datagram:\nSource Port: {src_port}, Destination Port: {dest_port}\n'

            elif ARP in packet:
                arp_src_ip = packet[ARP].psrc
                arp_dest_ip = packet[ARP].pdst
                output += f'ARP Packet:\nARP Source IP: {arp_src_ip}, ARP Destination IP: {arp_dest_ip}\n'

            # Enqueue the packet for the main thread to save
            self.packet_queue.put(output)

            # Update the packet display using after() on the main thread
            self.root.after(0, self.update_packet_display, output)

    def update_packet_display(self, output):
        self.packet_display.config(state=tk.NORMAL)
        self.packet_display.insert(tk.END, output)
        self.packet_display.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSnifferApp(root)
    root.mainloop()
