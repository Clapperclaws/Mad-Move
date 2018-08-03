timestamp=$(date +"%s")

#create directory with current timestamp
mkdir ${timestamp}

sudo ~/Desktop/carfi/carfi-supplicant -i wlo1 -d -c /etc/wpa_supplicant/madmove.conf -t > ${timestamp}/wpa_supplicant_${timestamp}.log &

sudo ~/Desktop/carfi/carfi-roamingd wlo1 &

#sudo iperf -c 35.180.29.183 -u -i 1 -t 600 > ${timestamp}/iperf_${timestamp}.log &
