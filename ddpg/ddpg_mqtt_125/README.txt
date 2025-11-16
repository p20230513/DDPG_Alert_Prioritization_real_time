1. Start Snort command:
sudo LD_LIBRARY_PATH=$VIRTUAL_ENV/snort3/lib $VIRTUAL_ENV/snort3/bin/snort \
  -c $VIRTUAL_ENV/snort3/etc/snort/snort.lua \
  -i lo \
  -A alert_fast \
  -l $VIRTUAL_ENV/snort3/var/log/snort

==> For Json Output
sudo LD_LIBRARY_PATH=$VIRTUAL_ENV/snort3/lib $VIRTUAL_ENV/snort3/bin/snort \
  -c $VIRTUAL_ENV/snort3/etc/snort/snort.lua \
  -i lo \
  -A alert_json \
  -l $VIRTUAL_ENV/snort3/var/log/snort


2. Scapy traffic generator command:
sudo -E $VIRTUAL_ENV/bin/python3.7 scapy_traffic.py --iface lo --ratio 0.4 --continuous

===================================================================================

==>Use run_realtime_pipeline.sh to start 
- snort
- scapy traffic generator
- evaluate_ddpg.py
