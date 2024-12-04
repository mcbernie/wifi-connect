#!/bin/bash


#trap "kill 0; iw dev ap del" EXIT

AR=$1
TIMEOUT=${AR:=300}

FILE=/var/CONFIGMODE
if [ -f "$FILE" ]; then
    TIMEOUT=480
fi

HOSTNAME=$(cat /etc/hostname)

GATEWAY_IP=10.0.0.1
DHCP_RANGE=10.0.0.2,10.0.0.40

echo "stop dnsmasq and hostapd"
/bin/systemctl stop dnsmasq
/bin/systemctl stop hostapd

kill $(pidof hostapd)
kill $(pidof dnsmasq)

echo "create interface and assign ip:"
iw phy phy0 interface add ap type __ap
sleep 2

echo "set mac address for ap"
# Der part ist nur für die Ubuntu Test Machine
ip link set dev ap address a4:b2:b0:bc:ca:05
sleep 1
systemctl restart NetworkManager
# Ende 

# echo "remove ip"
# ip addr del $GATEWAY_IP/24 dev ap
# sleep 1

sleep 1
echo "add ip"
ip addr add $GATEWAY_IP/24 dev ap

# Wichtig auch nur fuer das Test-System
echo "stoppe systemd-resolved, da dnsmasq den Port 53 brauch"
systemctl stop systemd-resolved

ss -lptn 'sport = :53'

echo "start dnsmasq"
dnsmasq \
	--address=/#/$GATEWAY_IP \
	--address=/portal.micast.local/$GATEWAY_IP \
	--dhcp-range=$DHCP_RANGE \
	--dhcp-option=option:router,$GATEWAY_IP \
	--dhcp-option=114,http://portal.micast.local \
	--dhcp-option=160,http://portal.micast.local \
	--interface=ap \
	--except-interface=lo \
	--bogus-priv \
	--domain-needed \
	--no-hosts \
	--keep-in-foreground &

echo "wait 5 seconds..."

sleep 5

echo "start hostapd"

cat <<EOT >> /tmp/hostapd.config
interface=ap
driver=nl80211
ssid=$HOSTNAME
channel=1
hw_mode=g
macaddr_acl=0
EOT

hostapd /tmp/hostapd.config &

sleep 1
echo "now you can run captive portal"

ip addr add $GATEWAY_IP/24 dev ap
#export RUST_LOG=debug 
#./target/debug/wifi-connect -u ./ui -t ./ui-configmode -s $HOSTNAME -a $TIMEOUT -g $GATEWAY_IP -w ap

echo "wait until CTRL+c"
read -r -d '' _ </dev/tty

echo "remove interface and ip assignment"
#ip addr del $GATEWAY_IP/24 dev ap
iw dev ap del


