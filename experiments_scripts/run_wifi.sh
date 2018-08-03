sudo pkill tcpdump
sudo pkill wpa_supplicant
sudo pkill carfi-supplicant
sudo pkill carfi-roamingd





timestamp=$(date +"%s")

#create directory with current timestamp
mkdir ${timestamp}

#sudo tcpdump -i wlo1 > ${timestamp}/wifi_${timestamp}.txt &
sudo tcpdump -i wlo1 -w ${timestamp}/wifi_${timestamp}.pcap &



#sudo ~/Desktop/carfi/carfi-supplicant -i wlo1 -d -c /etc/wpa_supplicant/madmove.conf -t > ${timestamp}/wpa_supplicant_${timestamp}.log &

sudo ~/Desktop/carfi/carfi-supplicant -Dnl80211 -i wlo1 -c /etc/wpa_supplicant/madmove.conf -dt > ${timestamp}/wpa_supplicant_${timestamp}.log &

#workload
python workloadWhenConnected.py ${timestamp} > ${timestamp}/workload_monitor_${timestamp}.txt &


#sudo ~/Desktop/carfi/carfi-roamingd wlo1 > ${timestamp}/wpa_supplicant_${timestamp}.log & 
sudo ~/Desktop/carfi/carfi-roamingd wlo1  |& ts '%.s:' |& tee  ${timestamp}/roamingd_${timestamp}.log 



# when connected, run: transmission-daemon --logfile ./filename


# ping and wget
