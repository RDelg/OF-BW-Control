#!/bin/bash
# Uso ./test.sh {DESTINO} [IP] {INICIO} [Mbps] {FIN} [Mbps] {INTERVALO} [Mbps] {TIEMPO} [Segs.] {DESCANSO} [Segs.]
# DEFAULT: ./test.sh 10.0.0.1 1 10 1 20 10

DESTINO=${1-'10.0.0.1'}
INICIO=${2-1}
FIN=${3-10}
INTERVALO=${4-1}
TIEMPO=${5-20}
DESCANSO=${6-10}

rm iperf.txt

for VARIABLE in $(eval echo "{$INICIO..$FIN..$INTERVALO}") 
do
		echo -n ${VARIABLE},$(date +%s), >> iperf.txt
        iperf -c ${DESTINO} -t ${TIEMPO} -u -b ${VARIABLE}M
        echo $(date +%s) >> iperf.txt
        sleep ${DESCANSO} 
done
