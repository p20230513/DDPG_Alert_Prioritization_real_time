##set $VITUAL_ENV PATH:
----------------------
source ~/ddpg_workspace/AlertPrioritization/venv37/bin/activate

## Start Snort and scapy traffic generator using below command:
--------------------------------------------------------------
sudo ./start_snort_scapy_gen.sh


## Training:
------------
cd src/
sudo -E $VIRTUAL_ENV/bin/python3.7 double_oracle.py realtime 1000 125 5 
OR
sudo -E $VIRTUAL_ENV/bin/python3.7 double_oracle.py alert_json.txt 1000 125 5

## Evaluation:
--------------
cd src/
sudo -E $VIRTUAL_ENV/bin/python3.7 evaluate_ddpg.py realtime rl 1000 125 rl 125 5 
OR
sudo -E $VIRTUAL_ENV/bin/python3.7 evaluate_ddpg.py alert_json.txt rl 1000 125 rl 125 5

## Analyse rewards_per_attacks.csv file 
