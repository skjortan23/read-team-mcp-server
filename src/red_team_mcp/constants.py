# Common network ports by category

# Web and HTTP related ports
webports = ['80', '443', '8080', '8081', '8443', '8888', '11434']

# Database ports
databaseports = ['1433', '1521', '3306', '5432', '6379', '27017', '27018', '27019', '5984', '9200', '9300']

# Mail service ports
mailports = ['25', '110', '143', '465', '587', '993', '995']

# FTP ports
ftpports = ['20', '21', '989', '990']

# SSH, Telnet and remote access
sshports = ['22', '23', '2222']

# DNS ports
dnsports = ['53', '853']

# LDAP ports
ldapports = ['389', '636']

# Remote desktop and VNC ports
rdpports = ['3389', '5900', '5901', '5902', '5903']

# SMB/CIFS ports
smbports = ['139', '445']

# Other common service ports
ntpports = ['123']
snmpports = ['161', '162']
vpnports = ['500', '1701', '1723', '4500']
printports = ['515', '631']
dhcpports = ['67', '68']
tftpports = ['69']
kafkaports = ['9092']
zookeeperports = ['2181']
elasticsearchports = ['9200', '9300']
memcachedports = ['11211']
mongodbports = ['27017', '27018', '27019']
redisports = ['6379']
rabbitmqports = ['5672', '15672']
cassandraports = ['7000', '7001', '9042']
etcdports = ['2379', '2380']
consulports = ['8300', '8301', '8302', '8500', '8600']
prometheusports = ['9090', '9091', '9093', '9094']
grafanaports = ['3000']
jenkinsports = ['8080']
kubernetesports = ['443', '6443', '8443', '10250', '10255', '10256']
dockerports = ['2375', '2376']

# All ports combined (unique values only)
allports = list(set(
    webports + 
    databaseports + 
    mailports + 
    ftpports + 
    sshports + 
    dnsports + 
    ldapports + 
    rdpports + 
    smbports + 
    ntpports + 
    snmpports + 
    vpnports + 
    printports + 
    dhcpports + 
    tftpports + 
    kafkaports + 
    zookeeperports + 
    elasticsearchports + 
    memcachedports + 
    mongodbports + 
    redisports + 
    rabbitmqports + 
    cassandraports + 
    etcdports + 
    consulports + 
    prometheusports + 
    grafanaports + 
    jenkinsports + 
    kubernetesports + 
    dockerports
))

def ports_by_service(service_name):
    """
    Returns a list of ports associated with the specified service.

    Args:
        service_name (str): The name of the service (e.g., 'http', 'ftp', 'ssh')

    Returns:
        list: A list of ports (as strings) associated with the service

    Raises:
        ValueError: If the service name is not recognized
    """
    service_name = service_name.lower()

    # Dictionary mapping service names to their port lists
    service_map = {
        # Web services
        'web': webports,
        'http': webports,
        'https': webports,

        # Database services
        'database': databaseports,
        'db': databaseports,
        'sql': databaseports,
        'mysql': ['3306'],
        'postgresql': ['5432'],
        'postgres': ['5432'],
        'oracle': ['1521'],
        'sqlserver': ['1433'],
        'redis': redisports,
        'mongodb': mongodbports,
        'mongo': mongodbports,
        'couchdb': ['5984'],
        'elasticsearch': elasticsearchports,

        # Mail services
        'mail': mailports,
        'smtp': ['25', '465', '587'],
        'pop3': ['110', '995'],
        'imap': ['143', '993'],

        # FTP services
        'ftp': ftpports,

        # SSH and Telnet
        'ssh': ['22', '2222'],
        'telnet': ['23'],

        # DNS services
        'dns': dnsports,

        # LDAP services
        'ldap': ldapports,

        # Remote desktop and VNC
        'rdp': ['3389'],
        'vnc': ['5900', '5901', '5902', '5903'],
        'remote': rdpports,

        # SMB/CIFS
        'smb': smbports,
        'cifs': smbports,

        # Other services
        'ntp': ntpports,
        'snmp': snmpports,
        'vpn': vpnports,
        'print': printports,
        'dhcp': dhcpports,
        'tftp': tftpports,
        'kafka': kafkaports,
        'zookeeper': zookeeperports,
        'memcached': memcachedports,
        'rabbitmq': rabbitmqports,
        'cassandra': cassandraports,
        'etcd': etcdports,
        'consul': consulports,
        'prometheus': prometheusports,
        'grafana': grafanaports,
        'jenkins': jenkinsports,
        'kubernetes': kubernetesports,
        'k8s': kubernetesports,
        'docker': dockerports,

        # All ports
        'all': allports
    }

    if service_name in service_map:
        return service_map[service_name]
    else:
        raise ValueError(f"Unknown service: {service_name}. Available services: {', '.join(sorted(service_map.keys()))}")
