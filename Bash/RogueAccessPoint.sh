#!/bin/bash
##### Defaults parameters
eth="eth0"         		#[ --wired ]
wlan="wlan0"       		#[ --wireless]
SSID="Evil"			#[ --ssid]
PASSWORD="Welkom01"		#[ --password]
CHANNEL="6"			#[ --channel]
DNS="8.8.8.8"			#[ --dns]
PORTS="80,443,8080,8443"	#[ --ports]
NOPROXY=""			#[ --noproxy]

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

##### The command line help
display_help() {
    echo "Usage: $0 [options...]" >&2
    echo
    echo "   -wired,		Set the wired interface 		default=\"eth0\""
    echo "   -wlan,		Set the wireless interface		default=\"wlan0\""
    echo "   -ssid,		Set the SSID of the AP			default=\"Evil\""
    echo "   -password,		Set the AP password			default=\"Welkom01\""
    echo "   -channel,		Set the channel of the AP		default=\"6\""
    echo "   -dns,		Set the DNS server for wlan		default=\"8.8.8.8\""
    echo "   -ports,		Set the ports to forward to Burp	default=\"80,443,8080,8443\""
    echo "   -noproxy		Disable port forwarding to Burp		default=\"False\""
    echo
    exit 1
}

##### Read command line arguments
while [[ "${#}" -gt 0 && ."${1}" == .-* ]]; do
  opt="${1}";
  case "$(echo ${opt} | tr '[:upper:]' '[:lower:]')" in
    -|-- ) break 2;;

    -wired|--wired )
      eth="${2}"
      shift 2;;
    -wireless|--wireless )
      wlan="${2}"
      shift 2;;
    -ssid|--ssid )
      SSID="${2}"
      shift 2;;
    -password|--password )
      PASSWORD="${2}"
      shift 2;;
    -channel|--channel )
      CHANNEL="${2}"
      shift 2;;
    -dns|--dns )
      DNS="${2}"
      shift 2;;
    -ports|--ports )
      PORTS="${2}"
      shift 2;;
    -norpoxy|--noproxy )
      NOPROXY="noproxy"
      shift 1;;
    -help|--help )
      display_help;;
    *) echo -e ' '${RED}'[!]'${RESET}" Unknown option: ${RED}${x}${RESET}" 1>&2 \
      && exit 1;;
   esac
done
clear

##### Trap ctrl-c and call ctrl_c()
trap ctrl_c INT
function ctrl_c() {
	echo -e ' '${YELLOW}'[-]'${RESET}' Removing iptables entries'${RESET} 1>&2
	iptables --table nat --flush
	iptables --flush
	sysctl net.ipv4.ip_forward=0 > /dev/null					# Disable routing
	kill $(cat /var/run/dnsmasq.pid)						# Disable DHCP/DNS server
	service hostapd stop
	service network-manager start
	echo -e ' '${YELLOW}'[-]'${RESET}' Rogue AP has shutdown'${RESET} 1>&2
	exit
}

##### Check prereqs
prereqs="dnsmasq hostapd"
for pkg in $prereqs ; do
	if dpkg --get-selections | grep -q "^$pkg[[:space:]]*install$" > /dev/null; then
		echo "$pkg is installed" > /dev/null
	else
		if apt-get -qq install $pkg; then
			echo -e ' '${GREEN}'[-]'${RESET}' Succesfully installed '${RED}$pkg${RESET} 1>&2
		else
			echo -e ' '${RED}'[!]'${RESET}' Error installing '${RED}$pkg${RESET} 1>&2
		fi
	fi
done

##### Check for devices
echo -e ' '${GREEN}'[-]'${RESET}' Checking devices...'${RESET} 1>&2
FINDETH=`grep "eth0" /proc/net/dev`
FINDWLAN=`grep "wlan0" /proc/net/dev`
if  [ -n "$FINDETH" ] ; then
	echo -e ' '${GREEN}'[-]'${RESET}' Wired is set to: '${RED}$eth${RESET} 1>&2
else
	echo -e ' '${RED}'[!]'${RESET}' Interface not found! check if '${RED}$eth${RESET}' and '${RED}$wlan${RESET}' are available' 1>&2
	exit
fi
if  [ -n "$FINDWLAN" ] ; then
	echo -e ' '${GREEN}'[-]'${RESET}' Wireless is set to: '${RED}$wlan${RESET}
else
	echo -e ' '${RED}'[!]'${RESET}' Interface not found! check if '${RED}$wlan${RESET}' is available' 1>&2
	exit
fi

##### Prepare Rogue Access Point
echo -e ' '${GREEN}'[-]'${RESET}' All prerequisites are met!'${RESET} 1>&2
cat >/etc/rap-hostapd.conf <<EOF
interface=$wlan
driver=nl80211
ssid=$SSID
hw_mode=g
channel=$CHANNEL
wpa=2
wpa_passphrase=$PASSWORD
EOF

##### Check network-manager service
service="NetworkManager"
if ps ax | grep -v grep | grep "NetworkManager" > /dev/null; then
	service network-manager stop
fi

##### Configure IP forwarding and stuff
ifconfig $wlan 192.168.101.1
service dnsmasq stop > /dev/null 											# Start DHCP/DNS server
dnsmasq --bind-interfaces --interface=$wlan --dhcp-range=192.168.101.2,192.168.101.250 --dhcp-option=3,192.168.101.1
sysctl net.ipv4.ip_forward=1 > /dev/null										# Enable routing
iptables --table nat --flush > /dev/null										# Enable NAT
iptables --flush > /dev/null
iptables --table nat --append POSTROUTING --out-interface $eth -j MASQUERADE -s 192.168.101.0/24			# Allow natting the traffic comes on wlan with source in IP 192.168.101.0/24 range
iptables --append FORWARD --in-interface $wlan -j ACCEPT								# Forward the traffic from wlan0 interface
iptables -t nat -A PREROUTING -i $wlan -p tcp --sport 53 -j DNAT --to-destination $DNS:53				# Forward DNS requests

if [ "${NOPROXY}" != "noproxy" ]; then
	iptables -t nat -A PREROUTING -i $wlan -p tcp --match multiport --dports $PORTS -j REDIRECT --to 8080		# Redirect HTTP traffic to burpsuite port 8080 and TRANSPARANT mode
	echo -e ' '${BOLD}'[-] Configure Burpsuite :'${RESET} 1>&2
	echo -e ' '${BOLD}'[-] 1. Listen on all interfaces'${RESET} 1>&2
	echo -e ' '${BOLD}'[-] 2. Enable invisible proxying'${RESET} 1>&2
	echo -e ' '${BOLD}'[-] 3. Disable the webinterface'${RESET} 1>&2
fi
echo -e ' '${GREEN}'[-] Starting Rogue AP with SSID: '${RED}$SSID${GREEN}' and Password '${RED}$PASSWORD${RESET} 1>&2
hostapd /etc/rap-hostapd.conf

##### Cleanup if something goes wrong
ctrl_c
