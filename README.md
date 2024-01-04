# Description:
The port scanning honeypot is a Python-based tool designed to detect and log suspicious port scanning activities on a network. Leveraging the Scapy library, the honeypot analyzes incoming packets, identifying SYN packets commonly associated with port scanning. This lightweight honeypot serves as an early warning system, allowing administrators to monitor and respond to potential security threats.

# Installation:
1. Dependencies:
   - Ensure you have Python installed on your system.
   - Install Scapy by running:
        ```
        pip install scapy  
        ```

2. Download the Honeypot Script:
   - Download the provided Python script (e.g., port_honeypot.py) to your preferred directory.
       ```
       git clone https://github.com/Toothless5143/Honeypot.git && cd Honeypot
       ```

# Usage:
1. Run the Honeypot:
   - Execute the script with administrative privileges:
       ```
       sudo python honeypot.py
       ```
   - The honeypot will start listening on the specified network interface (default is eth0).

2. Monitor Output:
   - The honeypot will print detected port scanning attempts in real-time.
   - Detected information includes the source IP, destination IP, and scanned port.

3. Adjust Configuration:
        Customize the script by modifying parameters such as the network interface or integrating additional logging mechanisms.

# Features:
1. Port Scan Detection:
   - Identifies SYN packets, indicative of port scanning activity.
2. Real-time Monitoring:
   - Provides real-time output of detected port scanning attempts.
3. Customizable Configuration:
   - Easily adjustable parameters, allowing users to tailor the honeypot to specific network environments.
4. Lightweight and Efficient:
   - Built using the Scapy library for efficient packet processing and minimal resource utilization.
5. Integration Potential:
   - Offers the flexibility to integrate with other security tools or logging mechanisms.
6. Early Warning System:
   - Serves as an early warning system for potential security threats, enabling proactive response.
  
# License:
This tool is open source and available under the [MIT License.](/LICENSE)
