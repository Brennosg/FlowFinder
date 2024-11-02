#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 


figlet -f slant "FlowFinder"


if [ -z "$1" ]; then
  echo -e "${RED}Uso: $0 <arquivo.pcap>${NC}"
  exit 1
fi


if [ ! -f "$1" ]; then
  echo -e "${RED}Erro: O arquivo '$1' não existe.${NC}"
  exit 1
fi


if ! command -v tshark &> /dev/null; then
  echo -e "${RED}Erro: tshark não está instalado. Instale-o com 'sudo apt install tshark'.${NC}"
  exit 1
fi


print_header() {
  echo -e "${BLUE}========================${NC}"
  echo -e "${YELLOW}$1${NC}"
  echo -e "${BLUE}========================${NC}"
}


top_ip_src() {
  print_header "IP com mais tráfego de origem"
  top_ip=$(tshark -r "$1" -T fields -e ip.src | sort | uniq -c | sort -nr | head -n 1)
  echo -e "${GREEN}$top_ip${NC}"
}


top_ip_dst() {
  print_header "IP com mais tráfego de destino"
  top_ip_dest=$(tshark -r "$1" -T fields -e ip.dst | sort | uniq -c | sort -nr | head -n 1)
  echo -e "${GREEN}$top_ip_dest${NC}"
}


top_protocols() {
  print_header "Protocolos mais usados"
  top_protocol=$(tshark -r "$1" -T fields -e _ws.col.Protocol | sort | uniq -c | sort -nr | head -n 5)
  echo -e "${GREEN}$top_protocol${NC}"
}


top_ips_by_bytes() {
  print_header "IPs com maior tráfego em bytes"
  echo -e "${GREEN}IP\t\t\tBytes${NC}"
  tshark -r "$1" -T fields -e ip.src -e frame.len | awk '{arr[$1]+=$2} END {for (ip in arr) printf "%s\t\t%d\n", ip, arr[ip]}' | sort -nr -k2 | head -n 5
}


top_ports() {
  print_header "Portas mais acessadas"
  echo -e "${GREEN}Porta\t\tContagem${NC}"
  top_ports=$(tshark -r "$1" -T fields -e tcp.dstport | sort | uniq -c | sort -nr | head -n 5)
  echo "$top_ports" | awk '{printf "%s\t\t%d\n", $2, $1}'
}


capture_period() {
  print_header "Período de captura"
  start_time=$(tshark -r "$1" -T fields -e frame.time_epoch | head -n 1)
  end_time=$(tshark -r "$1" -T fields -e frame.time_epoch | tail -n 1)
  echo -e "${GREEN}Início da captura: $(date -d @$start_time)${NC}"
  echo -e "${GREEN}Fim da captura: $(date -d @$end_time)${NC}"
}


icmp_count() {
  print_header "Total de pacotes ICMP"
  icmp_count=$(tshark -r "$1" -Y "icmp" | wc -l)
  echo -e "${GREEN}Total de pacotes ICMP: $icmp_count${NC}"
}


print_header "Escolha uma opção"
echo -e "${YELLOW}
1) IP com mais tráfego de origem
2) IP com mais tráfego de destino
3) Protocolos mais usados
4) IPs com maior tráfego em bytes
5) Portas mais acessadas
6) Período de captura
7) Pacotes ICMP
${NC}"

read -p "Digite o número da opção desejada: " opcao


case $opcao in
  1) top_ip_src "$1" ;;
  2) top_ip_dst "$1" ;;
  3) top_protocols "$1" ;;
  4) top_ips_by_bytes "$1" ;;
  5) top_ports "$1" ;;
  6) capture_period "$1" ;;
  7) icmp_count "$1" ;;
  *) echo -e "${RED}Opção inválida.${NC}" ;;
esac
