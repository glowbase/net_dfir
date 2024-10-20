#!/bin/bash

#set -x
clear
export GREP_COLORS="01;35"

RED='\033[31m'
GREEN='\033[32m'
BLUE='\033[34m'
CYAN='\033[35m'
RESET='\033[0m'
BOLD='\033[1m'
BOLD_PINK='\033[1;35m'
DIV="=============================="


BANNER="

███╗   ██╗███████╗████████╗    ██████╗ ███████╗██╗██████╗ 
████╗  ██║██╔════╝╚══██╔══╝    ██╔══██╗██╔════╝██║██╔══██╗
██╔██╗ ██║█████╗     ██║       ██║  ██║█████╗  ██║██████╔╝
██║╚██╗██║██╔══╝     ██║       ██║  ██║██╔══╝  ██║██╔══██╗
██║ ╚████║███████╗   ██║       ██████╔╝██║     ██║██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝       ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝

Perform basic network analysis on network captures.
"

OPTIONS=("PCAP")
SWITCHES=("-r", "--ipfix", "--cidr")
OPTION_IDX=0
REMOVAL_REQUIRED=0

for arg in "$@"; do
	if [ ! -z "$NEXT_ARG_VARIABLE" ]; then
		eval "${NEXT_ARG_VARIABLE}=\"$arg\""
		continue
	fi

	if [[ ${SWITCHES[@]} =~ $arg ]]; then
		case $arg in
		"-r")
			REMOVAL_REQUIRED=1
			;;
		"--ipfix")
			NEXT_ARG_VARIABLE="NETFLOW_FILE"
			;;
		"--cidr")
			NEXT_ARG_VARIABLE="CIDR"
			;;
		esac
		continue
	else

		case $OPTION_IDX in
			0)
				LOG_DIR="$arg"
				;;
			1)
				PCAP_FILE="$(realpath $arg)"
				TIMESTAMP="$(date +%y%m%d%H%M%S)"
				if [ -z "$LOG_DIR" ]; then
					LOG_DIR="$PCAP_FILE-$TIMESTAMP"
				fi
				;;
		esac
	
		((OPTION_IDX++))
	fi

done

if [ -z "$NETFLOW_FILE" ]; then
	NETFLOW_FILE="$LOG_DIR/netflow.silk"
fi

echo $NETFLOW_FILE
echo $LOG_DIR
echo $CIDR

# create the log dir if it doesn't exist
if [ ! -d "$LOG_DIR" ]; then
	mkdir $LOG_DIR
fi

log_header() {
	local heading=$1
	local sub_heading=$2

	if [ -z "$sub_heading" ]; then
		echo -e "${BLUE}${DIV}|${BOLD}${GREEN} ${heading} ${RESET}${BLUE}|${DIV}${RESET}"
	else
		echo -e "${BLUE}${DIV}|${BOLD}${GREEN} ${heading} - ${sub_heading} ${RESET}${BLUE}|${DIV}${RESET}"
	fi
}

log_value() {
	local title=$1
	local val=$2

	echo -e "${RED}${BOLD}[+] ${BLUE}${title}: ${RESET}${val}"
}

log_banner() {
	echo "$BANNER"
}

zeek_create() {
	ORIGINAL="$(pwd)"
	mkdir $LOG_DIR
	cd $LOG_DIR
	zeek -r $PCAP_FILE
	cd $ORIGINAL
}

netflow_create() {
	echo $(log_header "NETFLOW")
	echo

	rwp2yaf2silk --in $PCAP_FILE --out $NETFLOW_FILE
}

netflow_all_tcp_ports(){
	echo $(log_header "NETFLOW ALL TCP DESTINATION PORTS")
	echo

	# if the cidr is set, use it
	CIDR_FILTER=""
	if [ ! -z "$CIDR" ]; then
		CIDR_FILTER="--dcidr=$CIDR"
	fi

	rwfilter --type=all --proto=6 $CIDR_FILTER --flags-initial=S/SA --pass=stdout $NETFLOW_FILE | rwsort --field=stime | rwstats --fields=dport --count=1000
}

netflow_all_udp_ports(){
	echo $(log_header "NETFLOW ALL UDP DESTINATION PORTS")
	echo

	# if the cidr is not set exit with an error
	CIDR_FILTER=""
	if [ -z "$CIDR" ]; then
		echo $(log_value "CIDR" "CIDR is required for this analysis")
		return
	fi

	CIDR_FILTER="--dcidr=$CIDR"

	rwfilter --type=all --proto=17 $CIDR_FILTER --pass=stdout $NETFLOW_FILE | rwsort --field=stime | rwstats --fields=dport --values=records --threshold=3
}

netflow_excessive_unique_requests(){
	echo $(log_header "NETFLOW EXCESSIVE UNIQUE REQUESTS (<0.5s)")
	echo

	# if the cidr is set, use it
	CIDR_FILTER=""
	if [ ! -z "$CIDR" ]; then
		CIDR_FILTER="--dcidr=$CIDR"
	fi

	# Shows all source IPs that have made more than 10 unique requests to the same destination IP and port in less than 0.5 seconds
	rwfilter --type=all --proto=0-255 --pass=stdout $NETFLOW_FILE | rwfilter --duration=0.0-0.5 - --pass=stdout | rwsort --field=stime | rwuniq --fields=sip,dip,dport --values=distinct:sport --threshold=distinct:sport=10
}

netflow_all_ip_addresses(){
	echo $(log_header "NETFLOW ALL IP ADDRESSES")
	echo

	# Shows the count of all the records to each IP address
	(rwfilter --type=all --proto=0-255 --pass=stdout $NETFLOW_FILE | rwsort --field=stime | rwcut --fields=sip &&
        rwfilter --type=all --proto=0-255 --pass=stdout $NETFLOW_FILE | rwsort --field=stime | rwcut --fields=dip ) | sort | uniq -c | egrep -v "1\s+[sd]IP" | sort -nr
}

find_pe_files() {
	echo $(log_header "EXECUTABLES")
	echo

	cat $LOG_DIR/http.log | \
	zeek-cut -u ts id.orig_h id.orig_p id.resp_h id.resp_p resp_mime_types host uri | \
	grep "application/x-dosexec" | \
	awk '{$1=$1; printf "%s %s:%s %s:%s http://%s%s\n", $1, $2, $3, $4, $5, $7, $8}' | \
	column -t -s " "
	
	echo
}

map_active_directory() {
	echo $(log_header "ACTIVE DIRECTORY")
	echo

	local domain=$(cat $LOG_DIR/kerberos.log | zeek-cut service | grep krbtgt | head -n 1 | cut -d "/" -f 2)
	local dc_name=$(cat $LOG_DIR/kerberos.log | zeek-cut id.resp_h service | grep LDAP | head -n 1 | cut -d'/' -f2 | cut -d'.' -f1)
	local dc_ip=$(cat $LOG_DIR/kerberos.log | zeek-cut id.resp_h service | grep LDAP | head -n 1 | awk '{$1=$1; print}' | cut -d " " -f 1)

	echo $(log_value "FQDN" $domain)
	echo $(log_value "DC Name" $dc_name)
	echo $(log_value "DC IP" $dc_ip)

	# cat case001/kerberos.log | zcut id.orig_h id.resp_h id.resp_p request_type client service | head -n 1

	echo
}

zeek_remove() {
	rm -rf $LOG_DIR
}

execute_all() {
	log_banner
	netflow_create
	netflow_all_tcp_ports
	netflow_all_udp_ports
	netflow_all_ip_addresses
	netflow_excessive_unique_requests
	zeek_create
	find_pe_files
	map_active_directory

	# if REMOVAL_REQUIRED is set, mount the image
	if [ $REMOVAL_REQUIRED -eq 1 ]; then
		zeek_remove
	fi
}

execute_all
