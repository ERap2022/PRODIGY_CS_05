# Packet Sniffer Tool

## Description

The Packet Sniffer Tool is a real-time network packet capture and analysis application with a modern graphical user interface (GUI). It allows users to monitor network traffic, filter packets by protocol, and visualize packet data in a tabular format. The tool supports real-time updates and enables users to save captured data to a file.

## Features

- **Real-Time Packet Capture**: Capture and display network packets in real-time.
- **Protocol Filtering**: Filter packets based on protocol types (TCP, UDP, ICMP).
- **Packet Data Table**: View packet information in a table with dynamic numbering.
- **Status Bar**: Display real-time updates about the capture process, including the number of packets captured and the current filter applied.
- **Save to File**: Export captured packet data to a text file for further analysis.

## Installation

To set up the Packet Sniffer Tool, follow these steps:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/ERap2022/PRODIGY_CS_05.git
   ```

2. **Navigate to the Project Directory**:
   ```bash
   cd PRODIGY_CS_05
   ```

3. **Install Required Python Packages**:
   Ensure you have Python 3.x installed, then install the necessary packages using pip:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Run the Application**:
   Launch the Packet Sniffer Tool by running the following command:
   ```bash
   python Sniffer.py
   ```

2. **Interact with the GUI**:
   - Use the "Start Sniffing" button to begin capturing network packets.
   - Apply filters from the protocol dropdown to view specific types of packets.
   - Stop the capture using the "Stop Sniffing" button.
   - Save captured data to a file by clicking "Save to File."

3. **View Packet Data**:
   - The captured packets will be displayed in the main window.
   - Packet details, including source and destination IP addresses, protocol, and payload, will be shown in a table view.

## Requirements

- **Python 3.x**: The programming language used for development.
- **Scapy**: A powerful Python library used for packet manipulation and network traffic analysis.
- **Tkinter**: A standard GUI library for Python.
- **ttkthemes**: Provides themed widgets for a modern GUI appearance.

## Contributing

Contributions to the Packet Sniffer Tool are welcome! If you would like to contribute, please follow these guidelines:

1. **Fork the Repository**: Create your own fork of the repository.
2. **Create a Feature Branch**: Create a new branch for your feature or bug fix.
3. **Commit Your Changes**: Make sure your changes are well-documented in the commit messages.
4. **Push Your Changes**: Push your changes to your forked repository.
5. **Submit a Pull Request**: Open a pull request to merge your changes into the main repository.


## Contact

For any questions or feedback, you can reach out to me via [email](mailto:OJOOMONIYIDAMILOLA@gmail.com) 

---

Thank you for using the Packet Sniffer Tool!
```
