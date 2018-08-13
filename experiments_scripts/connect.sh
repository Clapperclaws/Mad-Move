#this script  connects to the wifi. Nothing more. No logs. Just to have some old good connectivity to Internet!
 sudo pkill tcpdump
 sudo pkill wpa_supplicant
sudo pkill carfi-supplicant
 sudo pkill carfi-roamingd



sudo ~/Desktop/carfi/carfi-supplicant -Dnl80211 -i wlo1 -c /etc/wpa_supplicant/madmove.conf  &

sudo ~/Desktop/carfi/carfi-roamingd wlo1 
