# ============================================================
# GENERATED MODEL PARAMETERS FROM ALERT ANALYSIS
# Copy these into test.py for model calibration
# ============================================================

from models import AlertType, PoissonDistribution

# Alert type definitions with Poisson means extracted from real data
ALERT_TYPES = [
    # ATTACKS (10 types)
    AlertType(2.0, PoissonDistribution(1.67), 't_SYN_FLOOD'),  # λ=1.67
    AlertType(1.0, PoissonDistribution(0.33), 't_PORT_SCAN'),  # λ=0.33
    AlertType(1.0, PoissonDistribution(1.67), 't_SQL_INJECTION'),  # λ=1.67
    AlertType(1.0, PoissonDistribution(0.67), 't_HTTP_C2'),  # λ=0.67
    AlertType(1.0, PoissonDistribution(0.5), 't_DNS_TUNNELING'),  # NOT OBSERVED - using default
    AlertType(1.0, PoissonDistribution(1.33), 't_BRUTE_FORCE'),  # λ=1.33
    AlertType(1.0, PoissonDistribution(0.67), 't_DDOS'),  # λ=0.67
    AlertType(1.0, PoissonDistribution(0.33), 't_XSS'),  # λ=0.33
    AlertType(1.0, PoissonDistribution(0.33), 't_COMMAND_INJECTION'),  # λ=0.33
    AlertType(1.0, PoissonDistribution(0.5), 't_MALWARE_DOWNLOAD'),  # NOT OBSERVED - using default

    # BENIGN (10 types)
    AlertType(1.0, PoissonDistribution(23.33), 't_BENIGN_HTTP'),  # λ=23.33
    AlertType(1.0, PoissonDistribution(21.67), 't_BENIGN_DNS'),  # λ=21.67
    AlertType(1.0, PoissonDistribution(28.00), 't_BENIGN_ICMP'),  # λ=28.00
    AlertType(1.0, PoissonDistribution(23.33), 't_BENIGN_SSH'),  # λ=23.33
    AlertType(1.0, PoissonDistribution(24.67), 't_BENIGN_TLS'),  # λ=24.67
    AlertType(1.0, PoissonDistribution(25.33), 't_BENIGN_SMTP'),  # λ=25.33
    AlertType(1.0, PoissonDistribution(22.33), 't_BENIGN_NTP'),  # λ=22.33
    AlertType(1.0, PoissonDistribution(26.33), 't_BENIGN_FTP'),  # λ=26.33
    AlertType(1.0, PoissonDistribution(22.67), 't_BENIGN_LDAP'),  # λ=22.67
    AlertType(1.0, PoissonDistribution(20.00), 't_BENIGN_MYSQL'),  # λ=20.00
]

# Statistics from analysis
TOTAL_ALERTS = 734
BENIGN_ALERTS = 713
ATTACK_ALERTS = 21
WINDOWS_COLLECTED = 3

# Per-window averages
AVG_BENIGN_PER_WINDOW = 237.7
AVG_ATTACKS_PER_WINDOW = 7.0