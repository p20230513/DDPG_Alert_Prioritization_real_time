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
classifications = {
    { name = 'not-suspicious', priority = 3 },
    { name = 'unknown', priority = 3 },
    { name = 'bad-unknown', priority = 2 },
    { name = 'attempted-recon', priority = 2 },
    { name = 'successful-recon-limited', priority = 2 },
    { name = 'successful-recon-largescale', priority = 2 },
    { name = 'attempted-dos', priority = 2 },
    { name = 'successful-dos', priority = 2 },
    { name = 'attempted-user', priority = 1 },
    { name = 'unsuccessful-user', priority = 1 },
    { name = 'successful-user', priority = 1 },
    { name = 'attempted-admin', priority = 1 },
    { name = 'successful-admin', priority = 1 },
    { name = 'rpc-portmap-decode', priority = 2 },
    { name = 'shellcode-detect', priority = 1 },
    { name = 'string-detect', priority = 3 },
    { name = 'suspicious-filename-detect', priority = 2 },
    { name = 'suspicious-login', priority = 2 },
    { name = 'system-call-detect', priority = 2 },
    { name = 'tcp-connection', priority = 4 },
    { name = 'trojan-activity', priority = 1 },
    { name = 'unusual-client-port-connection', priority = 2 },
    { name = 'network-scan', priority = 3 },
    { name = 'denial-of-service', priority = 2 },
    { name = 'non-standard-protocol', priority = 2 },
    { name = 'protocol-command-decode', priority = 3 },
    { name = 'web-application-activity', priority = 2 },
    { name = 'web-application-attack', priority = 1 },
    { name = 'misc-activity', priority = 3 },
    { name = 'misc-attack', priority = 2 },
    { name = 'icmp-event', priority = 3 },
    { name = 'inappropriate-content', priority = 1 },
    { name = 'policy-violation', priority = 1 },
    { name = 'default-login-attempt', priority = 2 },
    { name = 'sdf', priority = 2 },
    { name = 'file-format', priority = 1 },
    { name = 'malware-cnc', priority = 1 },
    { name = 'client-side-exploit', priority = 1 }
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
        RULE_PATH .. "/snort3-community.rules",
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
--output =
--{
--    {
--        name = 'alert_fast',
--        args = { file = '/home/vikash/ddpg_workspace/AlertPrioritization/venv37/snort3/var/log/snort/alert_fast.txt' }
--    },
--}

alert_fast = {
    file = true,
    packet = false
}

alert_json = {
    file = true,
    fields = 'timestamp pkt_num proto pkt_gen pkt_len dir src_ap dst_ap rule action'
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
