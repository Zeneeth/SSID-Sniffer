# SSID-Sniffer
A project to demonstrate what can be done with the directed probe requests that are being broadcast by your devices

## Installation
1. Install scapy - sudo pip3 install scapy
2. Clone repository - git clone https://github.com/Zeneeth/SSID-Sniffer
3. Set wifi card to monitor mode - sudo ifconfig wlan0 down && sudo iwconfig wlan0 mode monitor && sudo ifconfig wlan0 up
4. Run code - sudo python3 ssidSniffAndTrack.py
