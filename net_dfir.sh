#!/bin/bash

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
"

PCAP=$1
DIR=$PCAP.zeek

GEO_HIGHLIGHT="russia|iran|lithuania|china|cyprus|hong|kong|$"
AGENT_HIGHLIGHT="python|curl|wget|$"
HOST_HIGHLIGHT="python|simplehttp|$"
FILE_HIGHLIGHT="\.[a-zA-Z]+|$"
PORT_HIGHLIGHT="139|445|135|4444|9001|8080|8001|8000|3389$"
OBJECT_HIGHLIGHT="\.zip|\.rar|\.exe|$"

log_header() {
	local heading=$1
	local sub_heading=$2

	if [ -z "$sub_heading" ]; then
		echo -e "${BLUE}${DIV}[${BOLD}${GREEN} ${heading} ${RESET}${BLUE}]${DIV}${RESET}"
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

generate_zeek_output() {
    if [ ! -d "$DIR" ]; then
        echo "Generating Zeek Output..."
        echo

        zeek -r $PCAP
        mkdir $DIR
        mv *.log $DIR
    fi
}

mmdb_check() {
    if [ ! -x "$(command -v mmdblookup)" ]; then
        echo -e "${RED}Installing mmdblookup...${RESET}"
        sudo apt install libmaxminddb0 libmaxminddb-dev mmdb-bin geoipupdate -y
    fi

    if [ ! -f "/tmp/geo-city.mmdb" ]; then
        echo -e "${RED}Installing mmdb database...${RESET}"
        wget https://git.io/GeoLite2-City.mmdb -O /tmp/geo-city.mmdb &>/dev/null
    fi
}

download_threat_intel() {
    wget https://raw.githubusercontent.com/stamparm/ipsum/refs/heads/master/ipsum.txt -O /tmp/ipsum.txt &>/dev/null
}

get_environment() {
    echo $(log_header "ENVIRONMENT")
    echo

    local ad_domain=$(
        cat $DIR/kerberos.log | \
        zeek-cut service | \
        grep krbtgt | \
        head -n 1 | \
        cut -d "/" -f 2
    )

    echo $(log_value "AD Domain" $ad_domain)

    echo
}

get_active_directory() {
    echo $(log_header "DOMAIN CONTROLLER")
    echo

    dc_ip=$(
        cat $DIR/kerberos.log | \
        zeek-cut id.resp_h service | \
        grep LDAP | \
        head -n 1 | \
        awk '{$1=$1; print}' | \
        cut -d " " -f 1
    )

    echo $(log_value "IP Address" $dc_ip)

    dc_name=$(
        cat $DIR/kerberos.log | \
        zeek-cut id.resp_h service | \
        grep LDAP | \
        head -n 1 | \
        cut -d'/' -f2 | \
        cut -d'.' -f1
    )

    echo $(log_value "Hostname" $dc_name)

    dc_os=$(
        tshark -r $PCAP -Y "smb.native_os&&ip.src==$dc_ip" -T fields -e smb.native_os | \
        grep -v '^\s*$' | \
        sort | \
        uniq
    )

    echo $(log_value "Operating System" "$dc_os")

    dc_mac=$(
        tshark -r $PCAP -Y "ip.dst==$dc_ip" -T fields -e eth.dst | head -n 1
    )
    
    echo $(log_value "MAC Address" "$dc_mac")

    echo
}

get_win_computers() {
    echo $(log_header "WINDOWS HOSTS")
    echo

    local win_hosts=$(
        tshark -r $PCAP -Y "ip.dst!=$dc_ip&&kerberos.CNameString contains '$'" -T fields -e eth.src -e ip.src -e kerberos.CNameString | \
        awk '{print toupper($0)}' | \
        sed 's/\$//g' | \
        column -t | \
        sort | \
        uniq
    )

    echo "$win_hosts"

    echo
}

get_win_users() {
    echo $(log_header "WINDOWS USERS")
    echo

    local win_users=$(
        tshark -r $PCAP -Y "kerberos.CNameString&&ip.dst!=$dc_ip&& not (kerberos.CNameString contains '$')" -T fields -e eth.src -e ip.dst -e kerberos.CNameString | \
        column -t | \
        sort | \
        uniq
    )

    echo "$win_users"

    echo
}

get_dhcp_information() {
    echo $(log_header "DHCP")
    echo
    
    local dhcp_packets=$(tshark -r $PCAP -Y dhcp | wc -l)

    if [ $dhcp_packets != 0 ]; then
        local dhcp=$(
            tshark -r $PCAP -Y "dhcp.type==2" -T fields \
                -e dhcp.option.domain_name \
                -e dhcp.option.domain_name_server \
                -e dhcp.option.dhcp_server_id \
                -e dhcp.option.subnet_mask \
                -e dhcp.option.router | \
            column -t | \
            sort | \
            uniq
        )

        local dhcp_domain=$(echo $dhcp | cut -d " " -f 1)
        local dhcp_dns=$(echo $dhcp | cut -d " " -f 2)
        local dhcp_server=$(echo $dhcp | cut -d " " -f 3)
        local dhcp_subnet=$(echo $dhcp | cut -d " " -f 4)
        local dhcp_router=$(echo $dhcp | cut -d " " -f 5)

        echo $(log_value "Domain" $dhcp_domain)
        echo $(log_value "DNS" $dhcp_dns)
        echo $(log_value "Server" $dhcp_server)
        echo $(log_value "Subnet" $dhcp_subnet)
        echo $(log_value "Router" $dhcp_router)
    else
        echo "No DHCP Traffic..."
    fi

    echo
}

get_malicious_ips() {
    echo $(log_header "IP ADDRESSES")
    echo

    list=""
    ports=$(
        tshark -r $PCAP -T fields -e ip.src -e tcp.srcport | \
        awk '$2 <= 10000' | \
        sort | \
        uniq -c | \
        column -t
    )

    while IFS= read -r line; do
        local occurences=$(echo $line | cut -d " " -f 1)
        local ip=$(echo $line | cut -d " " -f 2)
        local port=$(echo $line | cut -d " " -f 3 | egrep --color=always $PORT_HIGHLIGHT)
        local country=$(
            mmdblookup -f /tmp/geo-city.mmdb -i $ip country names en 2>/dev/null | \
            cut -d '"' -f 2 | \
            egrep -v '^$' | \
            egrep -i --color=always $GEO_HIGHLIGHT
        )

        list+="$occurences,$ip,$port,$country\n"
    done <<< $ports

    echo -e "$list" | column -t -s "," | sort -k 1 -n -r | awk '$4 !=""'

    echo
}

get_user_agents() {
    echo $(log_header "USER AGENTS")
    echo

    tshark -r $PCAP -Y http.user_agent -T fields -e ip.src -e http.user_agent | \
    egrep -i --color=always $AGENT_HIGHLIGHT | \
    sort | \
    uniq -c | \
    sort -r

    echo
}

get_server_hosts() {
    echo $(log_header "SERVER HOSTS")
    echo

    tshark -r $PCAP -Y http.server -T fields -e ip.src -e http.server | \
    egrep -i --color=always $HOST_HIGHLIGHT | \
    sort | \
    uniq -c | \
    sort -r

    echo
}

get_uris() {
    echo $(log_header "REQUEST URI")
    echo

    list=""
    uris=$(
        tshark -r $PCAP -Y http.request.uri -T fields -e ip.dst -e tcp.dstport -e  http.request.uri | \
        egrep -i --color=always $FILE_HIGHLIGHT | \
        sort | \
        uniq -c | \
        column -t
    )

    while IFS= read -r line; do
        local occurences=$(echo $line | cut -d " " -f 1)
        local ip=$(echo $line | cut -d " " -f 2)
        local port=$(echo $line | cut -d " " -f 3)
        local path=$(echo $line | cut -d " " -f 4 | awk 'length > 130{$0=substr($0,0,131)"..."}1')

        list+="$occurences,$ip:$port,$path\n"
    done <<< $uris

    echo -e "$list" | column -t -s "," | sort -k 1 -n -r

    echo
}

get_external_connections() {
    echo $(log_header "EXTERNAL CONNECTIONS")
    echo

    list=""
    ports=$(
        tshark -r $PCAP -T fields -e ip.dst -e tcp.srcport | \
        awk '$2 <= 10000' | \
        sort | \
        uniq -c | \
        column -t
    )

    while IFS= read -r line; do
        local occurences=$(echo $line | cut -d " " -f 1)
        local ip=$(echo $line | cut -d " " -f 2)
        local port=$(echo $line | cut -d " " -f 3 | egrep --color=always $PORT_HIGHLIGHT)
        local country=$(
            mmdblookup -f /tmp/geo-city.mmdb -i $ip country names en 2>/dev/null | \
            cut -d '"' -f 2 | \
            egrep -v '^$' | \
            egrep -i --color=always $GEO_HIGHLIGHT
        )

        list+="$occurences,$ip,$port,$country\n"
    done <<< $ports

    echo -e "$list" | column -t -s "," | sort -k 1 -n -r | awk '$4 !=""'

    echo
}

get_http_objects() {
    echo $(log_header "HTTP OBJECTS")
    echo

    rm -rf http.files
    mkdir http.files

    tshark -r $PCAP --export-objects http,http.files &>/dev/null
    
    md5sum http.files/*.* | \
    sed 's/http\.files/ /g' | \
    tr '/' ' ' | \
    column -t | \
    egrep -i --color=always $OBJECT_HIGHLIGHT

    echo
}

execute_all() {
    log_banner
    mmdb_check
    download_threat_intel
    generate_zeek_output
    get_environment
    get_active_directory
    get_win_computers
    get_win_users
    get_dhcp_information
    get_malicious_ips
    get_user_agents
    get_server_hosts
    get_uris
    get_http_objects
    # get_external_connections
}

# execute_all

get_http_objects