# DigitalForensicTool (NetworkPacketAnalyzer)

    # Import necessary libraries
    import os
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    import pyshark
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk


    # Function to analyze a single PCAP file
    def analyze_pcap(file_path):
    try:
        # Open the PCAP file using pyshark 
        cap = pyshark.FileCapture(file_path, use_json=True)

        # Initialize a dictionary to store statistics
        stats = {
            "total_packets": 0,  # Total number of packets
            "protocols": {},     # Protocols and their counts
            "src_ips": {},       # Source IPs and their counts
            "dst_ips": {},       # Destination IPs and their counts
            "ports": {},         # Ports and their counts
            "ddos_suspected": False,  # Flag for DDoS detection
            "ddos_details": "",       # Details of DDoS detection
        }

        # Threshold for DDoS detection (number of requests to a single IP)
        ddos_threshold = 100
        ddos_ip_hits = {}  # Track hits per destination IP

        # Iterate through each packet in the PCAP file
        for packet in cap:
            stats["total_packets"] += 1  # Increment total packet count

            # Get the highest layer protocol (e.g., TCP, UDP, HTTP)
            protocol = packet.highest_layer
            stats["protocols"][protocol] = stats["protocols"].get(protocol, 0) + 1

            # Check if the packet has an IP layer
            if hasattr(packet, "ip"):
                # Extract source and destination IP addresses
                src_ip = packet.ip.src
                stats["src_ips"][src_ip] = stats["src_ips"].get(src_ip, 0) + 1
                dst_ip = packet.ip.dst
                stats["dst_ips"][dst_ip] = stats["dst_ips"].get(dst_ip, 0) + 1
                ddos_ip_hits[dst_ip] = ddos_ip_hits.get(dst_ip, 0) + 1

            # Check if the packet has a TCP or UDP layer
            if hasattr(packet, "tcp"):
                port = packet.tcp.dstport  # Extract destination port
                stats["ports"][port] = stats["ports"].get(port, 0) + 1
            elif hasattr(packet, "udp"):
                port = packet.udp.dstport  # Extract destination port
                stats["ports"][port] = stats["ports"].get(port, 0) + 1

        # Check for potential DDoS activity
        for dst_ip, hit_count in ddos_ip_hits.items():
            if hit_count > ddos_threshold:
                stats["ddos_suspected"] = True
                stats["ddos_details"] = f"Potential DDoS detected: {hit_count} requests to {dst_ip}"

        # Close the PCAP file
        cap.close()
        return stats

    except Exception as e:
        # Show an error message if something goes wrong
        messagebox.showerror("Error", f"Failed to analyze file {file_path}.\nError: {e}")
        return None


    # Function to preprocess data for readability
    def preprocess_data(data, top_n=10):
        # Sort the data by count in descending order
        sorted_data = sorted(data.items(), key=lambda x: x[1], reverse=True)
        # Get the top N items
        top_data = dict(sorted_data[:top_n])
        # If there are more items, group them as "Other"
        if len(sorted_data) > top_n:
            other_count = sum([x[1] for x in sorted_data[top_n:]])
            top_data["Other"] = other_count
        return top_data


    # Function to handle file selection and display results
    def select_and_analyze_file(canvas_frame, toolbar_frame, file_label, root):
    # Open a file dialog to select a PCAP file
    file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap;*.pcapng")])
        if not file_path:
            return

    # Extract only the file name from the full path
    file_name = os.path.basename(file_path)

    # Display the selected file name at the top
    file_label.config(text=f"Selected File: {file_name}", font=("Arial", 12, "bold"))

    # Clear the previous content in the canvas frame
    for widget in canvas_frame.winfo_children():
        widget.destroy()

    # Analyze the selected PCAP file
    stats = analyze_pcap(file_path)
    if stats:
        # Display the results in the GUI
        display_results(stats, file_path, canvas_frame, toolbar_frame, root)


    # Function to display results in the GUI
    def display_results(stats, file_path, canvas_frame, toolbar_frame, root):
        # Preprocess data for better readability
        protocols = preprocess_data(stats["protocols"], top_n=10)
        src_ips = preprocess_data(stats["src_ips"], top_n=10)
        dst_ips = preprocess_data(stats["dst_ips"], top_n=10)
        ports = preprocess_data(stats["ports"], top_n=10)

    # DDoS Detection Result
    ddos_label = tk.Label(canvas_frame, text="", font=("Arial", 14, "bold"), fg="red")
    ddos_label.pack(pady=10)
    if stats["ddos_suspected"]:
        ddos_label.config(text=f"WARNING: {stats['ddos_details']}")
    else:
        ddos_label.config(text="No DDoS activity detected.", fg="green")

    # Create a figure for the chart
    fig = Figure(figsize=(14, 10), facecolor="white")

    # Add Protocol Distribution chart
    ax1 = fig.add_subplot(221)
    ax1.bar(protocols.keys(), protocols.values(), color="blue")
    ax1.set_title("Protocol Distribution", pad=20)
    ax1.set_xlabel("Protocol")
    ax1.set_ylabel("Count")
    ax1.tick_params(axis="x", rotation=45, labelsize=8)

    # Add Source IP Distribution chart
    ax2 = fig.add_subplot(222)
    ax2.bar(src_ips.keys(), src_ips.values(), color="orange")
    ax2.set_title("Source IP Distribution", pad=20)
    ax2.set_xlabel("Source IP")
    ax2.set_ylabel("Count")
    ax2.tick_params(axis="x", rotation=45, labelsize=8)

    # Add Destination IP Distribution chart
    ax3 = fig.add_subplot(223)
    ax3.bar(dst_ips.keys(), dst_ips.values(), color="green")
    ax3.set_title("Destination IP Distribution", pad=20)
    ax3.set_xlabel("Destination IP")
    ax3.set_ylabel("Count")
    ax3.tick_params(axis="x", rotation=45, labelsize=8)

    # Add Port Distribution chart
    ax4 = fig.add_subplot(224)
    ax4.bar(ports.keys(), ports.values(), color="purple")
    ax4.set_title("Port Distribution", pad=20)
    ax4.set_xlabel("Port")
    ax4.set_ylabel("Count")
    ax4.tick_params(axis="x", rotation=45, labelsize=8)

    # Adjust layout for better spacing
    fig.tight_layout(pad=4.0)

    # Embed the chart in the GUI
    canvas = FigureCanvasTkAgg(fig, canvas_frame)
    canvas.get_tk_widget().pack(pady=20)

    # Clear the toolbar frame
    for widget in toolbar_frame.winfo_children():
        widget.destroy()

    # Add the toolbar for the chart (includes zoom, pan, and save)
    toolbar = NavigationToolbar2Tk(canvas, toolbar_frame)
    toolbar.update()
    toolbar.pack(side=tk.BOTTOM, fill=tk.X)

    # Add a button to show the summary
    summary_button = tk.Button(
        toolbar_frame,
        text="Show Summary",
        command=lambda: show_summary(stats, protocols, src_ips, dst_ips, ports),
        font=("Arial", 10),
        bg="lightblue",
    )
    summary_button.pack(side=tk.RIGHT, padx=5)


    # Function to show the summary in a pop-up window
    def show_summary(stats, protocols, src_ips, dst_ips, ports):
        # Create a new window for the summary
        summary_window = tk.Toplevel()
        summary_window.title("Summary of Findings")
        summary_window.geometry("1400x600")  # Wider window to accommodate side-by-side layout

    # Center the summary window on the screen
    screen_width = summary_window.winfo_screenwidth()
    screen_height = summary_window.winfo_screenheight()
    x = (screen_width // 2) - (1400 // 2)
    y = (screen_height // 2) - (600 // 2)
    summary_window.geometry(f"1400x600+{x}+{y}")

    # Add a frame for the title and total packets/ddos detection
    header_frame = tk.Frame(summary_window)
    header_frame.pack(fill=tk.X, pady=10)

    # Add the title (centered)
    title_label = tk.Label(header_frame, text="SUMMARY OF FINDINGS", font=("Arial", 16, "bold"))
    title_label.pack(pady=5)

    # Add Total Packets and DDoS Detection under the title
    total_packets_label = tk.Label(header_frame, text=f"Total Packets: {stats['total_packets']}", font=("Arial", 12, "bold"))
    total_packets_label.pack(pady=5)

    ddos_label = tk.Label(header_frame, text="DDoS Detection:", font=("Arial", 12, "bold"))
    ddos_label.pack(pady=5)
    if stats["ddos_suspected"]:
        ddos_result_label = tk.Label(header_frame, text=stats["ddos_details"], font=("Arial", 12), fg="red")
    else:
        ddos_result_label = tk.Label(header_frame, text="No DDoS activity detected.", font=("Arial", 12), fg="green")
    ddos_result_label.pack()

    # Add a frame for the summarization data (side by side)
    data_frame = tk.Frame(summary_window)
    data_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

    # Left column (Top Destination IPs)
    dst_ips_frame = tk.Frame(data_frame)
    dst_ips_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)

    dst_ips_label = tk.Label(dst_ips_frame, text="Top Destination IPs:", font=("Arial", 12, "bold"))
    dst_ips_label.pack(pady=5)
    for ip, count in dst_ips.items():
        ip_label = tk.Label(dst_ips_frame, text=f"{ip}: {count}", font=("Arial", 12))
        ip_label.pack()

    # Middle-left column (Top Source IPs)
    src_ips_frame = tk.Frame(data_frame)
    src_ips_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)

    src_ips_label = tk.Label(src_ips_frame, text="Top Source IPs:", font=("Arial", 12, "bold"))
    src_ips_label.pack(pady=5)
    for ip, count in src_ips.items():
        ip_label = tk.Label(src_ips_frame, text=f"{ip}: {count}", font=("Arial", 12))
        ip_label.pack()

    # Middle-right column (Top Protocols)
    protocols_frame = tk.Frame(data_frame)
    protocols_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)

    protocols_label = tk.Label(protocols_frame, text="Top Protocols:", font=("Arial", 12, "bold"))
    protocols_label.pack(pady=5)
    for protocol, count in protocols.items():
        protocol_label = tk.Label(protocols_frame, text=f"{protocol}: {count}", font=("Arial", 12))
        protocol_label.pack()

    # Right column (Top Ports)
    ports_frame = tk.Frame(data_frame)
    ports_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10)

    ports_label = tk.Label(ports_frame, text="Top Ports:", font=("Arial", 12, "bold"))
    ports_label.pack(pady=5)
    for port, count in ports.items():
        port_label = tk.Label(ports_frame, text=f"{port}: {count}", font=("Arial", 12))
        port_label.pack()


    # Main GUI application
    def main():
        # Create the main application window
        root = tk.Tk()
        root.title("Network Traffic Analyzer")

    # Set the initial window size to 50% of the original size
    window_width = 700  # 50% of 1400
    window_height = 450  # 50% of 900
    root.geometry(f"{window_width}x{window_height}")

    # Center the window on the screen
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width // 2) - (window_width // 2)
    y = (screen_height // 2) - (window_height // 2)
    root.geometry(f"{window_width}x{window_height}+{x}+{y}")

    # Add a welcoming banner with magnifying glass emojis
    welcome_label = tk.Label(
        root,
        text="🔍 NETWORK PACKET ANALYZER 🔍",  # Add emojis here
        font=("Arial", 14, "bold"),
        fg="black",
        bg="#B39EB5",
    )
    welcome_label.pack(pady=20)

    # Create a main frame with a scrollbar
    main_frame = tk.Frame(root)
    main_frame.pack(expand=True, fill="both", padx=10, pady=10)

    # Add a canvas for scrolling
    canvas = tk.Canvas(main_frame, highlightthickness=0)  # Remove black border
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Add a scrollbar
    scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=canvas.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Configure the canvas
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    # Create a frame inside the canvas to hold the content
    canvas_frame = tk.Frame(canvas)
    canvas.create_window((0, 0), window=canvas_frame, anchor="nw")

    # Toolbar frame
    toolbar_frame = tk.Frame(root)
    toolbar_frame.pack(fill=tk.X, padx=10, pady=5)

    # Label to display the selected file name
    file_label = tk.Label(root, text="", font=("Arial", 12, "bold"))
    file_label.pack(pady=10)

    # Create a frame to hold the buttons (Select and Close)
    button_frame = tk.Frame(root)
    button_frame.pack(pady=10)

    # Select file button
    select_button = tk.Button(
        button_frame,
        text="Select PCAP File",
        command=lambda: select_and_analyze_file(canvas_frame, toolbar_frame, file_label, root),
        font=("Arial", 12),
        bg="lightblue",
    )
    select_button.pack(side=tk.LEFT, padx=10)  # Place the button on the left

    # Close button
    close_button = tk.Button(
        button_frame,
        text="Close",
        command=root.destroy,  # Close the application
        font=("Arial", 12),
        bg="lightcoral",
    )
    close_button.pack(side=tk.LEFT, padx=10)  # Place the button on the right

    # Start the main application loop
    root.mainloop()


    # Run the application
    if __name__ == "__main__":
        main()
