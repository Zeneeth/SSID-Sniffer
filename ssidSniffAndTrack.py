from scapy.all import *
import threading
import json
import requests
import time


wigleuser = #PUT WIGLE API NAME HERE
wiglepass = #PUT WIGLE API TOKEN HERE
currentLat = 0
currentLon = 0
macssid = {}
ssidlocations = {}
welcome = [
"-----------------------------------------------------------------------------",
"   _____ _____ _____ _____     _____ _   _ _____ ______ ______ ______ _____  ",
"  / ____/ ____|_   _|  __ \\   / ____| \\ | |_   _|  ____|  ____|  ____|  __ \\ ",
" | (___| (___   | | | |  | | | (___ |  \\| | | | | |__  | |__  | |__  | |__) |",
"  \\___ \\\\___ \\  | | | |  | |  \\___ \\| . ` | | | |  __| |  __| |  __| |  _  / ",
"  ____) |___) |_| |_| |__| |  ____) | |\\  |_| |_| |    | |    | |____| | \\ \\ ",
" |_____/_____/|_____|_____/  |_____/|_| \\_|_____|_|    |_|    |______|_|  \\_\\",
"                                                                             ",
"-----------------------------------------------------------------------------"]

def findCurrentLocation():
    resp = requests.get(url="http://bot.whatismyipaddress.com/").text
    location = requests.get(url="http://ip-api.com/json/" + resp).json()
    currentLat = location['lat']
    currentLon = location['lon']

def findNetwork(ssid):
    payload = payload = {'ssid': ssid}
    resp = requests.get(url='https://api.wigle.net/api/v2/network/search', params=payload, auth=(wigleuser, wiglepass)).json()

    if resp['success']:
        if resp['totalResults'] == 0:
            #print("Did not find a network with that name")
            return "none found"
        elif resp['totalResults'] > 1:
            print("Found several networks with that name, the network could be at the following locations")
            for i in range(0, resp['totalResults']):
                print(resp['results'][i]['trilat'], resp['results'][i]['trilong'])
            return "lots"
        else:
            print("Network is likely to be at:", resp['results'][0]['trilat'], resp['results'][0]['trilong'])
            return str(resp['results'][0]['trilat'], resp['results'][0]['trilong'])
    else:
        return "Response failed:", resp['message']

def packetCheck(pkt):
    if pkt.type == 0 and pkt.subtype == 4:
        ssid = str(pkt.info)[2:-1]
        sendermac = str(pkt.addr2)
        if sendermac in macssid:
            if ssid not in macssid[sendermac]:
                 if ssid != '':
                    macssid[sendermac].add(ssid)
        else:
            if ssid != '':
                macssid[sendermac] = {ssid}
        if ssid not in ssidlocations:
            ssidlocations[ssid] = findNetwork(ssid) 

def directedProbeRequestSniffer():
    while(True):
        try:
            sniff(iface="wlan0",prn=packetCheck)
        except:
            print("There was an error trying to start sniffing for packets, please check your network card setup")
            break
    os._exit(-1)

def main():
    findCurrentLocation()
    sniffThread = threading.Thread(target=directedProbeRequestSniffer)
    sniffThread.setDaemon(True)
    sniffThread.start()
    time.sleep(2)
    for i in welcome:
        print(i)
    print("Started sniffing for directed probe requests")
    running = True
    while(running):
        choice = input("Please choose from the following (list, exit, locations): ")
        if choice == "list" or choice == "l":
            print("---------------")
            for j in macssid:
                print(j, macssid[j])
            print("---------------")
        elif choice == "exit":
            running = False
            print("Stopping the sniff")
        elif choice == "locations":
            print("---------------")
            for i in ssidlocations:
                print(i, ssidlocations[i])
            print("---------------")
if __name__ == "__main__":
    main()
