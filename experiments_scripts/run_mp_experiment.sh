 sudo pkill tcpdump
 sudo pkill wpa_supplicant
sudo pkill carfi-supplicant
 sudo pkill carfi-roamingd


mv in_progress/1* "test_dir"

timestamp=$(date +"%s")


sudo ip link set dev enp0s20u3u3 multipath backup


#create directory with current timestamp
mkdir "in_progress/"${timestamp}

#Start tcpdump on wireless interface
#sudo tcpdump -i wlo1 -w ${timestamp}/wifi_${timestamp}.pcap &
sudo tcpdump -i wlo1 --buffer-size=50000 -w  "in_progress/"${timestamp}/wifi_${timestamp}.pcap &


#Start tcpdump on lte interface
#en_name="$(ifconfig | grep 4163 | grep -v wlo1 | awk -F ":" '{print $1}')"

en_name="$(ifconfig -s | grep  BMRU |  grep -v wlo1 | awk  '{print $1}')"   ### add "| grep enp0 |" if needed

en_name="$(ip link | grep enp | grep -v 'NO-CAR' | awk '{print $2}'| awk -F ":" '{print $1}')"

#en_name="enp0s20u3u3"


#sudo tcpdump -i ${en_name} -w ${timestamp}/lte_${timestamp}.pcap &
sudo tcpdump -i ${en_name} --buffer-size=50000 -w   "in_progress/"${timestamp}/lte_${timestamp}.pcap &

#######google-chrome "file:///media/ubuntu/79bf333c-7b40-4765-9e0a-c16fa2b41163/muse/dash.js/samples/dash-if-reference-player/index.html"	&


#sudo  wpa_supplicant -i wlo1 -c /etc/wpa_supplicant/wpa_supplicant_eap-sim.conf -t > ${timestamp}/wpa_supplicant_${timestamp}.log

#sudo ~/Desktop/carfi/carfi-supplicant -i wlo1 -d -c /etc/wpa_supplicant/madmove.conf -t > ${timestamp}/wpa_supplicant_${timestamp}.log &

#sudo ~/Desktop/carfi/carfi-roamingd wlo1 &


ping -i 0.2 8.8.8.8 -D > "in_progress/"${timestamp}/ping_${timestamp}.txt &


sudo python /media/ubuntu/79bf333c-7b40-4765-9e0a-c16fa2b41163/muse/git/Mad-Move/experiments_scripts/fix_dhcp.py >> "in_progress/"${timestamp}/ip_monitor_${timestamp}.txt 2>&1 &


sudo ~/Desktop/carfi/carfi-supplicant -Dnl80211 -i wlo1 -c /etc/wpa_supplicant/madmove.conf -dt >  "in_progress/"${timestamp}/wpa_supplicant_${timestamp}.log &


#sudo ~/Desktop/carfi/carfi-roamingd wlo1 > ${timestamp}/wpa_supplicant_${timestamp}.log & 
sudo ~/Desktop/carfi/carfi-roamingd wlo1  |& ts '%.s:' |& tee   "in_progress/"${timestamp}/roamingd_${timestamp}.log 






#@watch 'echo -n `date +"%s"`" " >> test.log; ip tcp_metrics show 35.180.29.183 >> test.log'
#watch 'echo -n "time: "`date +"%s"`" " >> test.log; ip tcp_metrics show | grep '35.180.29.183' >> test.log' &



##ping and wget
###workload
# wget -c http://35.180.117.76:8080/download/ubuntu.iso
#google-chrome "file:///media/ubuntu/79bf333c-7b40-4765-9e0a-c16fa2b41163/muse/dash.js/samples/dash-if-reference-player/index.html"
##### http://35.180.117.76:8080/video/manifest.mpd
