#!/bin/bash
# Variables
#########################
# The defaults          #
#########################

eth="eth0"         	#[ --wired ]
wlan="wlan0"       	#[ --wireless]
SSID="Evil"		#[ --ssid]
PASSWORD="Welkom01"	#[ --password]
CHANNEL="6"		#[ --channel]

RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

#########################
# The command line help #
#########################
display_help() {
    echo "Usage: $0 [option...]" >&2
    echo
    echo "   -wired,		Set the wired interface 	default = eth0"
    echo "   -wlan,		Set the wireless interface	default = wlan0"
    echo "   -ssid,		Set the SSID of the AP		default = Evil"
    echo "   -password,		Set the AP password		default = Welkom01"
    echo "   -channel,		Set the channel of the AP	default = 6"
    echo
    exit 1
}

while [[ "${#}" -gt 0 && ."${1}" == .-* ]]; do
  opt="${1}";
  shift;
  case "$(echo ${opt} | tr '[:upper:]' '[:lower:]')" in
    -|-- ) break 2;;

    -wired|--wired )
      eth="${1}";;
    -wireless|--wireless )
      wlan="${1}";;
    -ssid|--ssid )
      SSID="${1}";;
    -password|--password )
      PASSWORD="${1}";;
    -channel|--channel )
      CHANNEL="${1}";;
    -help|--help )
      display_help;;
    *) echo -e ' '${RED}'[!]'${RESET}" Unknown option: ${RED}${x}${RESET}" 1>&2 \
      && exit 1;;
   esac
done
clear
echo -e ' '${YELLOW}'[-]'${RESET}' Wired is set to: '${RED}$eth${RESET}' and wireless to: '${RED}$wlan${RESET} 1>&2

# trap ctrl-c and call ctrl_c()
trap ctrl_c INT

function ctrl_c() {
        # Stop and cleanup
	echo -e ' '${YELLOW}'[-]'${RESET}' Removing iptables entries'${RESET} 1>&2
	iptables --table nat --flush
	iptables --flush
	## Disable routing
	sysctl net.ipv4.ip_forward=0 > /dev/null
	# Disable DHCP/DNS server
	kill $(cat /var/run/dnsmasq.pid)
	service hostapd stop
	service network-manager start
	echo -e ' '${YELLOW}'[-]'${RESET}' Rogue AP has shutdown'${RESET} 1>&2
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
echo -e ' '${GREEN}'[-]'${RESET}' All prerequisites are installed'${RESET} 1>&2

# /etc/rap-hostapd.conf
cat >/etc/rap-hostapd.conf <<EOF
interface=$wlan
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
wpa=2
wpa_passphrase=$PASSWORD
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
# Redirect HTTP traffic to burpsuite port 8080 and TRANSPARANT mode
iptables -t nat -A PREROUTING -i $wlan -p tcp --dport 80 -j REDIRECT --to 8080
iptables -t nat -A PREROUTING -i $wlan -p tcp --dport 8080  -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i $wlan -p tcp --dport 443 -j REDIRECT --to 8080
iptables -t nat -A PREROUTING -i $wlan -p tcp --dport 8443 -j REDIRECT --to-port 8080
# Setup DNS
iptables -t nat -A PREROUTING -i $wlan -p tcp --sport 53 -j DNAT --to-destination 8.8.8.8:53
# Run access point daemon
echo -e ' '${BOLD}'[-] Configure Burpsuite :'${RESET} 1>&2
echo -e ' '${BOLD}'[-] 1. Listen on all interfaces'${RESET} 1>&2
echo -e ' '${BOLD}'[-] 2. Enable invisible proxying'${RESET} 1>&2
echo -e ' '${BOLD}'[-] 3. Disable the webinterface'${RESET} 1>&2
echo -e ' '${GREEN}'[-] Starting Rogue AP with SSID: '${RED}$SSID${GREEN}' and Password '${RED}$PASSWORD${RESET} 1>&2
hostapd /etc/rap-hostapd.conf
# Stop and cleanup
echo -e ' '${YELLOW}'[-]'${RESET}' Removing iptables entries'${RESET} 1>&2
iptables --table nat --flush
iptables --flush
## Disable routing
sysctl net.ipv4.ip_forward=0 > /dev/null
# Disable DHCP/DNS server
kill $(cat /var/run/dnsmasq.pid)
service hostapd stop
service network-manager start
echo -e ' '${YELLOW}'[-]'${RESET}' Rogue AP has been shutdown'${RESET} 1>&2
