---------------------------------------------------------------------------
-- Snort 3 Configuration with Community Rules
---------------------------------------------------------------------------

-- Get the snort installation directory
--SNORT_DIR = os.getenv('VIRTUAL_ENV') .. '/snort3'

-- Paths
SNORT_DIR = '/home/vikash/ddpg_workspace/AlertPrioritization/venv37/snort3'
RULE_PATH = SNORT_DIR .. '/etc/snort/rules'
---------------------------------------------------------------------------
-- Network Variables (MUST be defined before ips)
---------------------------------------------------------------------------
HOME_NET = 'any'
EXTERNAL_NET = 'any'

DNS_SERVERS = HOME_NET
SMTP_SERVERS = HOME_NET
HTTP_SERVERS = HOME_NET
SQL_SERVERS = HOME_NET
TELNET_SERVERS = HOME_NET
SSH_SERVERS = HOME_NET
FTP_SERVERS = HOME_NET
SIP_SERVERS = HOME_NET

HTTP_PORTS = '80 8080 8180 8888'
SHELLCODE_PORTS = '!80'
ORACLE_PORTS = '1024:'
SSH_PORTS = '22'
FTP_PORTS = '21 2100 3535'
SIP_PORTS = '5060 5061 5600'
FILE_DATA_PORTS = '80 8080 8180 8888 110 143'
GTP_PORTS = '2123 2152 3386'

AIM_SERVERS = [[
    64.12.24.0/23,64.12.28.0/23,64.12.161.0/24,64.12.163.0/24,
    64.12.200.0/24,205.188.3.0/24,205.188.5.0/24,
    205.188.7.0/24,205.188.9.0/24,205.188.153.0/24,
    205.188.179.0/24,205.188.248.0/24
]]

---------------------------------------------------------------------------
-- Classification Configuration
---------------------------------------------------------------------------
---------------------------------------------------------------------------
-- classifications
---------------------------------------------------------------------------

classifications = {
    { name = 'not-suspicious', priority = 3, text = 'Not Suspicious Traffic' },
    { name = 'unknown', priority = 3, text = 'Unknown Traffic' },
    { name = 'bad-unknown', priority = 2, text = 'Potentially Bad Traffic' },
    { name = 'attempted-recon', priority = 2, text = 'Attempted Information Leak' },
    { name = 'successful-recon-limited', priority = 2, text = 'Information Leak' },
    { name = 'successful-recon-largescale', priority = 2, text = 'Large Scale Information Leak' },
    { name = 'attempted-dos', priority = 2, text = 'Attempted Denial of Service' },
    { name = 'successful-dos', priority = 2, text = 'Denial of Service' },
    { name = 'attempted-user', priority = 1, text = 'Attempted User Privilege Gain' },
    { name = 'unsuccessful-user', priority = 1, text = 'Unsuccessful User Privilege Gain' },
    { name = 'successful-user', priority = 1, text = 'Successful User Privilege Gain' },
    { name = 'attempted-admin', priority = 1, text = 'Attempted Administrator Privilege Gain' },
    { name = 'successful-admin', priority = 1, text = 'Successful Administrator Privilege Gain' },
    { name = 'rpc-portmap-decode', priority = 2, text = 'Decode of an RPC Query' },
    { name = 'shellcode-detect', priority = 1, text = 'Executable Code was Detected' },
    { name = 'string-detect', priority = 3, text = 'A Suspicious String was Detected' },
    { name = 'suspicious-filename-detect', priority = 2, text = 'A Suspicious Filename was Detected' },
    { name = 'suspicious-login', priority = 2, text = 'An Attempted Login Using a Suspicious Username was Detected' },
    { name = 'system-call-detect', priority = 2, text = 'A System Call was Detected' },
    { name = 'tcp-connection', priority = 4, text = 'A TCP Connection was Detected' },
    { name = 'trojan-activity', priority = 1, text = 'A Network Trojan was Detected' },
    { name = 'unusual-client-port-connection', priority = 2, text = 'A Client was Using an Unusual Port' },
    { name = 'network-scan', priority = 3, text = 'Detection of a Network Scan' },
    { name = 'denial-of-service', priority = 2, text = 'Detection of a Denial of Service Attack' },
    { name = 'non-standard-protocol', priority = 2, text = 'Detection of a Non-Standard Protocol or Event' },
    { name = 'protocol-command-decode', priority = 3, text = 'Generic Protocol Command Decode' },
    { name = 'web-application-activity', priority = 2, text = 'Access to a Potentially Vulnerable Web Application' },
    { name = 'web-application-attack', priority = 1, text = 'Web Application Attack' },
    { name = 'misc-activity', priority = 3, text = 'Misc Activity' },
    { name = 'misc-attack', priority = 2, text = 'Misc Attack' },
    { name = 'icmp-event', priority = 3, text = 'Generic ICMP Event' },
    { name = 'inappropriate-content', priority = 1, text = 'Inappropriate Content was Detected' },
    { name = 'policy-violation', priority = 1, text = 'Potential Corporate Privacy Violation' },
    { name = 'default-login-attempt', priority = 2, text = 'Attempt to Login By a Default Username and Password' },
    { name = 'sdf', priority = 2, text = 'Sensitive Data was Transmitted Across the Network' },
    { name = 'file-format', priority = 1, text = 'A File Format was Detected' },
    { name = 'malware-cnc', priority = 1, text = 'Known Malware Command and Control Traffic Detected' },
}
---------------------------------------------------------------------------
-- Configure IPS with inline variables
---------------------------------------------------------------------------
ips =
{
    enable_builtin_rules = true,

    variables =
    {
        nets =
        {
            HOME_NET = HOME_NET,
            EXTERNAL_NET = EXTERNAL_NET,
            DNS_SERVERS = DNS_SERVERS,
            SMTP_SERVERS = SMTP_SERVERS,
            HTTP_SERVERS = HTTP_SERVERS,
            SQL_SERVERS = SQL_SERVERS,
            TELNET_SERVERS = TELNET_SERVERS,
            SSH_SERVERS = SSH_SERVERS,
            FTP_SERVERS = FTP_SERVERS,
            SIP_SERVERS = SIP_SERVERS,
            AIM_SERVERS = AIM_SERVERS
        },

        ports =
        {
            HTTP_PORTS = HTTP_PORTS,
            SHELLCODE_PORTS = SHELLCODE_PORTS,
            ORACLE_PORTS = ORACLE_PORTS,
            SSH_PORTS = SSH_PORTS,
            FTP_PORTS = FTP_PORTS,
            SIP_PORTS = SIP_PORTS,
            FILE_DATA_PORTS = FILE_DATA_PORTS,
            GTP_PORTS = GTP_PORTS
        }
    },

    include =
    {
        -- RULE_PATH .. "/snort3-community.rules",
        RULE_PATH .. "/local.rules"
    }
}
---------------------------------------------------------------------------
-- Detection (uses default settings)
---------------------------------------------------------------------------
-- Snort 3 uses optimal detection methods automatically
---------------------------------------------------------------------------
-- Output
---------------------------------------------------------------------------
-- ==============================================================
-- Output Configuration
-- ==============================================================

alert_fast = {
    file = true,
    limit = 200,
    packet = false,
}

alert_json = {
    file = true,
    limit = 200,
    fields = 'timestamp proto src_ap dst_ap rule action msg sid class priority'
}
---------------------------------------------------------------------------
-- Network protocols
---------------------------------------------------------------------------
stream = { }
stream_tcp = { }
stream_ip = { }
stream_icmp = { }
stream_udp = { }

normalizer = {
    tcp = {
        ips = true
    }
}

---------------------------------------------------------------------------
-- DAQ configuration
---------------------------------------------------------------------------
daq = { }
