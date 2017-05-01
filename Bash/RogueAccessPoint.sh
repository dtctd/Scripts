#!/bin/bash
# Variables
eth=$1
wlan=$2
# Check parameters
if [[ $# -ne 2 ]]; then
	echo "Usage: $0 wiredinterface wirelessinterface"
	exit 1
fi

# trap ctrl-c and call ctrl_c()
trap ctrl_c INT

function ctrl_c() {
        # Stop and cleanup
	echo "[-] Removing iptables entries..."
	iptables --table nat --flush
	iptables --flush
	## Disable routing
	sysctl net.ipv4.ip_forward=0 > /dev/null
	# Disable DHCP/DNS server
	kill $(cat /var/run/dnsmasq.pid)
	service hostapd stop
	service network-manager start
	echo "[-] Rogue AP has been shutdown"
}

# Check prereqs
prereqs="dnsmasq hostapd"
for pkg in $prereqs ; do
	if dpkg --get-selections | grep -q "^$pkg[[:space:]]*install$" > /dev/null; then
		echo "$pkg is installed" > /dev/null
	else
		if apt-get -qq install $pkg; then
			echo "Succesfully installed $pkg"
		else
			echo "Error installing $pkg"
		fi
	fi
done
echo "[-] All prerequirements are installed"

# /etc/rap-hostapd.conf
cat >/etc/rap-hostapd.conf <<EOF
interface=$wlan
driver=nl80211
ssid=Evil
hw_mode=g
channel=6
wpa=2
wpa_passphrase=Welkom01
EOF

# Check network-manager service
service="NetworkManager"
if ps ax | grep -v grep | grep "NetworkManager" > /dev/null; then
	service network-manager stop
fi

# Start
# Configure IP address for WLAN
ifconfig $wlan 192.168.101.1
# Start DHCP/DNS server
service dnsmasq stop > /dev/null
dnsmasq --bind-interfaces --interface=$wlan --dhcp-range=192.168.101.2,192.168.101.250 --dhcp-option=3,192.168.101.1
# Enable routing
sysctl net.ipv4.ip_forward=1 > /dev/null
# Enable NAT
iptables --table nat --flush > /dev/null
iptables --flush > /dev/null
# Allow natting the traffic comes on wlan with source in IP 192.168.101.0/24 range
iptables --table nat --append POSTROUTING --out-interface $eth -j MASQUERADE -s 192.168.101.0/24
# Forward the traffic from wlan0 interface
iptables --append FORWARD --in-interface $wlan -j ACCEPT
# Redirect HTTP traffic to burpsuite port 8082 and TRANSPARANT mode
iptables -t nat -A PREROUTING -i $wlan -p tcp --dport 80 -j REDIRECT --to 8081
iptables -t nat -A PREROUTING -i $wlan -p tcp --dport 8080  -j REDIRECT --to-port 8081
iptables -t nat -A PREROUTING -i $wlan -p tcp --dport 443 -j REDIRECT --to 8081
iptables -t nat -A PREROUTING -i $wlan -p tcp --dport 8443 -j REDIRECT --to-port 8081
# Setup DNS
iptables -t nat -A PREROUTING -i $wlan -p tcp --sport 53 -j DNAT --to-destination 8.8.8.8:53
# Run access point daemon
echo "[-] Configure Burp proxy:"
echo "[-] 1. Listen on all interfaces"
echo "[-] 2. Enable invisible proxying"
echo "[-] 3. Disable the webinterface"
echo -e "\e[32m[-] Starting Rogue AP with SSID: \e[39mEvil\e[32m and Password: \e[39mWelkom01"
hostapd /etc/rap-hostapd.conf
# Stop and cleanup
echo "[-] Removing iptables entries..."
iptables --table nat --flush
iptables --flush
## Disable routing
sysctl net.ipv4.ip_forward=0 > /dev/null
# Disable DHCP/DNS server
kill $(cat /var/run/dnsmasq.pid)
service hostapd stop
service network-manager start
echo "[-] Rogue AP has been shutdown"
