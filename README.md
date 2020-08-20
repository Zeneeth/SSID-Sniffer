# SSID-Sniffer
A project to demonstrate what can be done with the directed probe requests that are being broadcast by your devices

## Installation
1. Install scapy - ```sudo pip3 install scapy```
2. Clone repository - ```git clone https://github.com/Zeneeth/SSID-Sniffer```
3. Set wifi card to monitor mode - ```sudo ifconfig wlan0 down && sudo iwconfig wlan0 mode monitor && sudo ifconfig wlan0 up```
4. Run code - ```sudo python3 ssidSniffAndTrack.py```

## Overview
This project is intended to show how much information can be gathered about you from the probe requests that your devices are making. It does this by listening to all nearby packets, then filtering this down to only contain directed probe requests (probe requests that specify the ssid of the network). This could contain the names of your home network, work network - essentially any network that you have connected to and have allowed your device to 'automatically connect' to. These packets contain the mac address of the device looking for the network and the name of the network you are trying to connect to, the code will discard the rest of the data in this packet. From network names, we can attempt to locate the network. We have done this using wigle, which has a database with network names, bssids and locations. This will not always work perfectly - the network name may not appear in the database which means we cannot guess where the network is, or there may be lots of entries for one ssid in the database - in this case we will locate the closest network to the user's location and store that, or the network may have moved since it was added to the database. The location that gets returned from wigle is stored with that network name.
