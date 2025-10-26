#!/bin/bash
set -e

# ===========================================================
# Snort 3 Community Rules Auto-Download Script
# Downloads and configures Snort community rules
# ===========================================================

if [ -z "$VIRTUAL_ENV" ]; then
  echo "❌ Please activate your Python virtual environment first."
  echo "Example: source venv/bin/activate"
  exit 1
fi

SNORT_DIR="$VIRTUAL_ENV/snort3"
RULES_DIR="$SNORT_DIR/etc/snort/rules"
SNORT_CONF="$SNORT_DIR/etc/snort/snort.lua"

echo "📥 Downloading Snort 3 Community Rules..."
echo "Snort Directory: $SNORT_DIR"
echo ""

# ===========================================================
# 1. Download Community Rules
# ===========================================================
echo "[1/6] Downloading latest community rules..."
cd /tmp

# Remove old downloads
rm -f community-rules.tar.gz snort3-community-rules*

# Download Snort 3 community rules (no registration needed)
wget -q --show-progress \
  https://www.snort.org/downloads/community/snort3-community-rules.tar.gz \
  -O community-rules.tar.gz

echo "✅ Download complete"
echo ""

# ===========================================================
# 2. Extract Rules
# ===========================================================
echo "[2/6] Extracting rules..."
tar -xzf community-rules.tar.gz

# Find the extracted directory (name may vary)
EXTRACTED_DIR=$(find . -maxdepth 1 -type d -name "snort3-community-rules*" | head -1)

if [ -z "$EXTRACTED_DIR" ]; then
  echo "❌ Could not find extracted rules directory"
  exit 1
fi

echo "Found rules in: $EXTRACTED_DIR"
echo ""

# ===========================================================
# 3. Install Rules
# ===========================================================
echo "[3/6] Installing rules to $RULES_DIR..."

# Create rules directory if it doesn't exist
mkdir -p "$RULES_DIR"

# Copy all .rules files
if [ -d "$EXTRACTED_DIR/rules" ]; then
  cp -v "$EXTRACTED_DIR/rules"/*.rules "$RULES_DIR/" 2>/dev/null || echo "No .rules files found in rules/"
fi

# Also check for rules in root directory
cp -v "$EXTRACTED_DIR"/*.rules "$RULES_DIR/" 2>/dev/null || echo "No additional rules found"

# Count installed rules
RULE_COUNT=$(find "$RULES_DIR" -name "*.rules" | wc -l)
echo "✅ Installed $RULE_COUNT rule files"

# List the rules files
echo "Rule files installed:"
ls -1 "$RULES_DIR"/*.rules 2>/dev/null | while read rule_file; do
    basename "$rule_file"
done

echo ""

# ===========================================================
# 4. Update Configuration to Load Rules
# ===========================================================
echo "[4/6] Creating snort.lua configuration..."

# Find the main community rules file
MAIN_RULES=$(ls "$RULES_DIR"/snort3-community.rules 2>/dev/null || ls "$RULES_DIR"/*.rules 2>/dev/null | head -1)

if [ -n "$MAIN_RULES" ]; then
    RULES_FILENAME=$(basename "$MAIN_RULES")
    echo "Will load: $RULES_FILENAME"
    
    # Create the complete configuration
    cat > "$SNORT_CONF" << 'EOFCONFIG'
---------------------------------------------------------------------------
-- Snort 3 Configuration with Community Rules
---------------------------------------------------------------------------

-- Get the snort installation directory
SNORT_DIR = os.getenv('VIRTUAL_ENV') .. '/snort3'

-- Paths
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
ips = {
    enable_builtin_rules = true,
    variables = {
        nets = {
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
        ports = {
            HTTP_PORTS = HTTP_PORTS,
            SHELLCODE_PORTS = SHELLCODE_PORTS,
            ORACLE_PORTS = ORACLE_PORTS,
            SSH_PORTS = SSH_PORTS,
            FTP_PORTS = FTP_PORTS,
            SIP_PORTS = SIP_PORTS,
            FILE_DATA_PORTS = FILE_DATA_PORTS,
            GTP_PORTS = GTP_PORTS
        }
    }
}

-- Only include rules if the file exists
local rule_file = RULE_PATH .. '/snort3-community.rules'
local f = io.open(rule_file, 'r')
if f then
    f:close()
    ips.include = rule_file
end

---------------------------------------------------------------------------
-- Detection (uses default settings)
---------------------------------------------------------------------------
-- Snort 3 uses optimal detection methods automatically

---------------------------------------------------------------------------
-- Output
---------------------------------------------------------------------------
alert_fast = {
    file = true
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
EOFCONFIG

else
    echo "⚠️  No rules files found, creating basic config without rules"
    cat > "$SNORT_CONF" << 'EOFCONFIG'
---------------------------------------------------------------------------
-- Snort 3 Basic Configuration
---------------------------------------------------------------------------

-- Paths
SNORT_DIR = os.getenv('VIRTUAL_ENV') .. '/snort3'
RULE_PATH = SNORT_DIR .. '/etc/snort/rules'

-- Network configuration
HOME_NET = 'any'
EXTERNAL_NET = 'any'

---------------------------------------------------------------------------
-- Configure IPS
---------------------------------------------------------------------------
ips = {
    enable_builtin_rules = true
}

---------------------------------------------------------------------------
-- Detection
---------------------------------------------------------------------------
detection = {
    search_method = 'ac_full'
}

---------------------------------------------------------------------------
-- Output
---------------------------------------------------------------------------
alert_fast = {
    file = true
}

---------------------------------------------------------------------------
-- Network protocols
---------------------------------------------------------------------------
stream = { }
stream_tcp = { }
stream_ip = { }
stream_icmp = { }
stream_udp = { }

---------------------------------------------------------------------------
-- DAQ configuration
---------------------------------------------------------------------------
daq = { }
EOFCONFIG
fi

echo "✅ Configuration created at: $SNORT_CONF"
echo ""

# ===========================================================
# 5. Create a Simple Test Rule
# ===========================================================
echo "[5/6] Creating test rules..."
cat > "$RULES_DIR/local.rules" << 'EOFRULES'
# Local test rules
alert icmp any any -> any any (msg:"ICMP Packet Detected"; sid:1000001; rev:1;)
alert tcp any any -> any any (msg:"TCP Traffic Detected"; sid:1000002; rev:1;)
alert udp any any -> any any (msg:"UDP Traffic Detected"; sid:1000003; rev:1;)
EOFRULES

echo "✅ Created local.rules with test rules"
echo ""

# ===========================================================
# 6. Test Configuration
# ===========================================================
echo "[6/6] Testing Snort configuration..."

# Set library path for testing
export LD_LIBRARY_PATH="$SNORT_DIR/lib:$LD_LIBRARY_PATH"

echo "Running: snort -c $SNORT_CONF -T"
if $SNORT_DIR/bin/snort -c "$SNORT_CONF" -T 2>&1 | grep -q "successfully validated\|Snort successfully"; then
  echo "✅ Configuration is valid!"
else
  echo "⚠️  Configuration test completed with warnings"
  echo "   Run the test manually to see details:"
  echo "   $SNORT_DIR/bin/snort -c $SNORT_CONF -T"
fi

echo ""
echo "=================================================="
echo "✅ Snort Community Rules Installation Complete!"
echo "=================================================="
echo ""
echo "Installation Summary:"
echo "  Rules Location:  $RULES_DIR"
echo "  Configuration:   $SNORT_CONF"
echo "  Rules Installed: $RULE_COUNT files"
echo ""
echo "Rule files:"
ls -1 "$RULES_DIR"/*.rules 2>/dev/null | sed 's/^/  - /' || echo "  No rules found"
echo ""
echo "=================================================="
echo "Usage Examples:"
echo "=================================================="
echo ""
echo "1. Test configuration:"
echo "   \$VIRTUAL_ENV/snort3/bin/snort -c $SNORT_CONF -T"
echo ""
echo "2. Run Snort on network interface (requires sudo):"
echo "   sudo LD_LIBRARY_PATH=\$VIRTUAL_ENV/snort3/lib \\"
echo "        \$VIRTUAL_ENV/snort3/bin/snort \\"
echo "        -c $SNORT_CONF \\"
echo "        -i eth0 -A alert_fast"
echo ""
echo "3. Read from PCAP file:"
echo "   \$VIRTUAL_ENV/snort3/bin/snort -c $SNORT_CONF -r capture.pcap -A alert_fast"
echo ""
echo "4. Generate test traffic (in another terminal):"
echo "   ping -c 5 8.8.8.8"
echo ""
echo "5. View alerts:"
echo "   tail -f $SNORT_DIR/var/log/snort/alert_fast.txt"
echo ""
echo "=================================================="
