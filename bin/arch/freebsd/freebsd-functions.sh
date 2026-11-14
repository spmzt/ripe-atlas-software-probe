# Shell functions for FreeBSD: the Linux ones, except those that use /proc,
# /sys or Linux-only commands.
. $ATLAS_SCRIPTS/linux-functions.sh

RESOLV_CONF=/etc/resolv.conf

buddyinfo()
{
	$ATLAS_MEASUREMENT/buddyinfo "$@"
	set $(sysctl -n vm.stats.vm.v_free_count vm.stats.vm.v_page_size)
	[ $(expr $1 \* $2 / 1024) -gt 2048 ]
}
check_pid()
{
	ps -p "$@" > /dev/null 2>&1
}
kill_perds()
{
	# The applets run as busybox: match the name they were started as
	pkill -9 -f '^([^ ]*/)?(perd|eperd|eooqd)( |$)'
}
sos()
{
	## sos
	UPTIME=`onlyuptime`
	INFO="$1"
	CLOCK="$(date '+%s')"
	if [ -n "$INFO" ]; then INFO="$INFO".; fi
	evping -e -c 2 "${INFO}C${CLOCK}.U$UPTIME.M$ETHER_SCANNED.$(get_sos_server)"
}
get_ether_addr()
{
	# The MAC address of the interface with the default route, IPv4
	# first
	dev=$(route -n get -inet default 2>/dev/null |
		sed -n 's/^ *interface: //p')
	if [ -z "$dev" ] ; then
		dev=$(route -n get -inet6 default 2>/dev/null |
			sed -n 's/^ *interface: //p')
	fi
	ETHER_ADDR=
	if [ -n "$dev" ] ; then
		ETHER_ADDR=$(ifconfig "$dev" ether 2>/dev/null |
			sed -n 's/^[[:space:]]*ether //p')
	fi
	export ETHER_ADDR
	ETHER_SCANNED=`echo $ETHER_ADDR | sed -e s/\://g`; export ETHER_SCANNED
}
dump_interfaces()
{
	ifconfig -a
	netstat -ibnW
}
