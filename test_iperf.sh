#!/bin/bash
# Uso ./test.sh {DESTINO} [IP] {INICIO} [Mbps] {FIN} [Mbps] {INTERVALO} [Mbps]
# DEFAULT: ./test.sh 10.0.0.1 1 10 1

DESTINO=${1-'10.0.0.1'}
INICIO=${2-1}
FIN=${3-10}
INTERVALO=${4-1}

rm iperf.txt

for VARIABLE in $(eval echo "{$INICIO..$FIN..$INTERVALO}") 
do
		echo -n ${VARIABLE},$(date +%s), >> iperf.txt
        iperf -c ${DESTINO} -t 20 -u -b ${VARIABLE}M
        echo $(date +%s) >> iperf.txt
        sleep 10 
done
