sudo pkill tcpdump
sudo pkill wpa_supplicant
sudo pkill carfi-supplicant
sudo pkill carfi-roamingd



mv in_progress/1* "test_dir"


timestamp=$(date +"%s")

#create directory with current timestamp
mkdir "in_progress/"${timestamp}

#sudo tcpdump -i wlo1 > ${timestamp}/wifi_${timestamp}.txt &
sudo tcpdump -i wlo1 --buffer-size=50000 -w "in_progress/"${timestamp}/wifi_${timestamp}.pcap &



#sudo ~/Desktop/carfi/carfi-supplicant -i wlo1 -d -c /etc/wpa_supplicant/madmove.conf -t > ${timestamp}/wpa_supplicant_${timestamp}.log &

sudo ~/Desktop/carfi/carfi-supplicant -Dnl80211 -i wlo1 -c /etc/wpa_supplicant/madmove.conf -dt > "in_progress/"${timestamp}/wpa_supplicant_${timestamp}.log &

#workload
python workloadWhenConnected.py "in_progress/"${timestamp} >> "in_progress/"${timestamp}/workload_monitor_${timestamp}.txt 2>&1 &

#sudo ~/Desktop/carfi/carfi-roamingd wlo1 > ${timestamp}/wpa_supplicant_${timestamp}.log & 
sudo ~/Desktop/carfi/carfi-roamingd wlo1  |& ts '%.s:' |& tee  "in_progress/"${timestamp}/roamingd_${timestamp}.log 



# when connected, run: transmission-daemon --logfile ./filename


# ping and wget
