from scapy.all import *
import base64
import threading
import json
import requests
import time
import math
import webbrowser

wigleuser = # wigle api name
wiglepass = # wigle api token

browser = webbrowser.get()
currentLat = 51.509865
currentLon = -0.118092
ssidlocmac = {}
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
    try:
        resp = requests.get(url="http://bot.whatismyipaddress.com/").text
        location = requests.get(url="http://ip-api.com/json/" + resp).json()
        currentLat = location['lat']
        currentLon = location['lon']
    except:
        print("Could not get location using the internet so defaulted to central london")

def calculateDistance(lat1, lon1, lat2, lon2):
    R = 6378100
    φ1 = lat1 * math.pi/180
    φ2 = lat2 * math.pi/180
    Δφ = (lat2-lat1) * math.pi/180
    Δλ = (lon2-lon1) * math.pi/180

    a = math.sin(Δφ/2) * math.sin(Δφ/2) + math.cos(φ1) * math.cos(φ2) * math.sin(Δλ/2) * math.sin(Δλ/2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

    d = R * c

    return d

def findNetwork(ssid):
    try:
        payload = {'ssid': ssid, 'resultsPerPage': 1000}
        resp = requests.get(url='https://api.wigle.net/api/v2/network/search', params=payload, auth=(wigleuser, wiglepass)).json()

        if resp['success']:
            if resp['totalResults'] == 0:
                return "NR"
            elif resp['totalResults'] > 1:
                minDistance = calculateDistance(currentLat, currentLon, resp['results'][0]['trilat'], resp['results'][0]['trilong'])
                minIndex = 0
                for i in range(1, resp['resultCount']):
                    if minDistance > calculateDistance(currentLat, currentLon, resp['results'][i]['trilat'], resp['results'][i]['trilong']):
                        minDistance = calculateDistance(currentLat, currentLon, resp['results'][i]['trilat'], resp['results'][i]['trilong'])
                        minIndex = i
                return str(resp['results'][minIndex]['trilat']) + ", " + str(resp['results'][minIndex]['trilong'])
            else:
                return str(resp['results'][0]['trilat']) + ", " + str(resp['results'][0]['trilong'])
        elif resp['message'] == 'too many queries today':
            return ">Q"
        else:
            print(resp['message'])
            return "ER"
    except:
        print("COMMAND ERROR")
        return "ER"

def packetCheck(pkt):
    if pkt.type == 0 and pkt.subtype == 4:
        ssid = str(pkt.info)[2:-1]
        sendermac = str(pkt.addr2)
        if ssid != '':
            if ssid in ssidlocmac:
                if sendermac not in ssidlocmac[ssid][1]:
                    ssidlocmac[ssid][1].add(sendermac)
            else:
                ssidlocmac[ssid] = ["NT", {sendermac}]

def findSSIDsFromMac(mac):
    ssidsFound = []
    for x in ssidlocmac:
        if mac in ssidlocmac[x][1]:
            ssidsFound.append(x)
    return ssidsFound

def directedProbeRequestSniffer():
    while(True):
        try:
            sniff(iface="wlan0",prn=packetCheck,store=False)
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
        choice = input("Please choose from the following (help, listssid, listmac, tracemac, findssid, exit): ")
        if choice == "help" or choice == "h":
            print("---------------")
            print("COMMANDS")
            print("help(h)     : displays this information")
            print("listssid(ls): lists all the SSIDs that have devices have looked for, and the status of the network location")
            print("listmac(lm) : lists all the mac addresses that have looked for networks, and the SSIDs of any networks they have looked for")
            print("tracemac(t) : will ask for the mac address to trace (lower case), will then attempt to locate all networks that device has looked for and plot them on a map")
            print("findssid(f) : will search for that SSID (even if it has not been sniffed) and plot the location on a map")
            print("exit(e)     : ends the program")
            print("~~~~~~")
            print("LOCATION STATUS CODES")
            print("Once the program has discovered an SSID, the list commands with either display the latitude and longitude of that network, or one of the following codes")
            print("NT : Not yet attempted to locate network")
            print("NF : Network location could not be found using wigle")
            print("ER : Error retrieving location - normally caused by an invalid api key")
            print(">Q : The api key has reached its daily query limit")
            print("---------------")

        elif choice == "listssid" or choice == "ls":
            print("---------------")
            for j in ssidlocmac:
                print(j, ssidlocmac[j])
            print("---------------")
        elif choice == "listmac" or choice == "lm":
            print("---------------")
            maclist = {}
            for x in ssidlocmac:
                for y in ssidlocmac[x][1]:
                    if y in maclist:
                        maclist[y].add(x + " (" + str(ssidlocmac[x][0]) + ")")
                    else:
                        maclist[y] = {x + " (" + str(ssidlocmac[x][0]) + ")"}
            for x in maclist:
                print(x + " " + str(maclist[x]))
            print("---------------")
        elif choice == "tracemac" or choice == "t":
            mac = input("Please input the mac address: ")
            print("---------------")
            ssids = findSSIDsFromMac(mac)
            if len(ssids) == 0:
                print("No SSIDs found - please check you typed the mac correctly")
            else:
                locations = ''
                print(mac + " has tried to conenct to the following ssids:")
                for x in ssids:
                    print(x)
                    if ssidlocmac[x][0] == 'NT':
                        ssidlocmac[x][0] = findNetwork(x)
                    if ssidlocmac[x][0] == 'ER' or ssidlocmac[x][0] == 'NR' or ssidlocmac[x][0] == '>Q':
                        print("No location for", x, "so will not be on map")
                    else:
                        locations = locations + ssidlocmac[x][0] + ","
                locations = locations[0:-1]
                if len(locations)>0:
                    try:
                        browser.open("http://localhost?coordinates=" + str(base64.b64encode(locations.encode("utf-8")), "utf-8"), new=0)
                    except:
                        pass
                else:
                    print("No locations found for those ssids")
            print("---------------")

        elif choice == "findssid" or choice == "f":
            ssid = input ("Please input the SSID of the network: ")
            ssid = str(ssid)
            location = ''
            print("---------------")
            if ssid not in ssidlocmac:
                print("That network has not been sniffed, but will attempt to locate it anyway")
                location = 'NT'
            else:
                location = ssidlocmac[ssid][0]
            if location == 'NT':
                location = findNetwork(ssid)
                if ssid in ssidlocmac:
                    ssidlocmac[ssid][0] = location
            if location == 'ER' or location == 'NR' or location == '>Q':
                print("No location found for", ssid)
            else:
                try:
                    browser.open("http://localhost?coordinates=" + str(base64.b64encode(location.encode("utf-8")), "utf-8"), new=0)
                except:
                    pass
            print("---------------")
        elif choice == "exit" or choice == "e":
            running = False
            print("Stopping the sniff")
if __name__ == "__main__":
    main()
