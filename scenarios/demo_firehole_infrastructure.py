from netaddr import IPAddress, IPNetwork
from cyst.api.configuration import (
    AuthenticationProviderConfig,
    PassiveServiceConfig,
    AccessSchemeConfig,
    AuthorizationDomainConfig,
    AuthorizationDomainType,
    AuthorizationConfig,
    NodeConfig,
    InterfaceConfig,
    ActiveServiceConfig,
    RouterConfig,
    ConnectionConfig,
    FirewallConfig,
    FirewallChainConfig,
    ExploitConfig,
    ExploitCategory,
    ExploitLocality,
    VulnerableServiceConfig,
    DataConfig,
    RouteConfig,
)
from cyst.api.environment.configuration import ServiceParameter
from cyst.api.logic.access import (
    AccessLevel,
    AuthenticationProviderType,
    AuthenticationTokenType,
    AuthenticationTokenSecurity,
)
from cyst.api.network.firewall import FirewallPolicy, FirewallChainType, FirewallRule
from pathlib import Path


# -----------------------------------------------------------------------------
# Files
# -----------------------------------------------------------------------------
with open(f"{Path(__file__).parent}/fh-wp.yml") as f:
    file_fh_wp = f.read()

with open(f"{Path(__file__).parent}/fh-mysql.yml") as f:
    file_fh_mysql = f.read()

with open(f"{Path(__file__).parent}/fh-vsftpd.yml") as f:
    file_fh_vsftpd = f.read()

with open(f"{Path(__file__).parent}/fh-smb.yml") as f:
    file_fh_smb = f.read()

with open(f"{Path(__file__).parent}/db_fix.sh") as f:
    db_fix = f.read()

# -----------------------------------------------------------------------------
# Network definitions
# -----------------------------------------------------------------------------
network_outside = IPNetwork("192.168.0.0/24")
network_public = IPNetwork("192.168.1.0/24")
network_internal = IPNetwork("192.168.2.0/24")
network_server = IPNetwork("192.168.3.0/24")

# -----------------------------------------------------------------------------
# Local password authentication template
# -----------------------------------------------------------------------------
auth_local_password = AuthenticationProviderConfig(
    provider_type=AuthenticationProviderType.LOCAL,
    token_type=AuthenticationTokenType.PASSWORD,
    token_security=AuthenticationTokenSecurity.SEALED,
    timeout=30,
)

# -----------------------------------------------------------------------------
# Node definitions
# -----------------------------------------------------------------------------
node_attacker = NodeConfig(
    active_services=[ActiveServiceConfig("scripted_actor", "scripted_attacker", "attacker", AccessLevel.LIMITED)],
    passive_services=[
        # PassiveServiceConfig(
        #     type="empire", owner="empire", version="4.10.0", access_level=AccessLevel.LIMITED
        # ),
        PassiveServiceConfig(
            name="metasploit", owner="msf", version="6.4.42", local=True, access_level=AccessLevel.LIMITED
        ),
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress(network_outside.first + 10), network_outside)],
    shell="",
    id="node_attacker",
)

node_dns = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            name="coredns",
            owner="coredns",
            version="1.11.1",
            local=False,
            access_level=AccessLevel.LIMITED,
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress(network_outside.first + 2), network_outside)],
    shell="",
    id="node_dns",
)

node_wordpress = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            name="wordpress",
            owner="root",
            version="6.1.1",
            local=False,
            access_level=AccessLevel.LIMITED,
            authentication_providers=[auth_local_password("wordpress_pwd")],
            access_schemes=[
                AccessSchemeConfig(
                    authentication_providers=["wordpress_pwd"],
                    authorization_domain=AuthorizationDomainConfig(
                        type=AuthorizationDomainType.LOCAL,
                        authorizations=[AuthorizationConfig("root", AccessLevel.ELEVATED)],
                    ),
                )
            ],
            private_data=[
                DataConfig(id="/firehole-config.yml", description=file_fh_wp, owner="root")
            ]
        ),
        PassiveServiceConfig(
            name="netcat-traditional",
            owner="root",
            version="1.2.3",
            local=True,
            access_level=AccessLevel.ELEVATED,
        ),
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress(network_public.first + 10), network_public)],
    shell="",
    id="node_wordpress",
)

node_database = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            name="mysql",
            owner="root",
            version="8.0.31",
            local=False,
            access_level=AccessLevel.LIMITED,
            authentication_providers=[auth_local_password("mysql_pwd")],
            access_schemes=[
                AccessSchemeConfig(
                    authentication_providers=["mysql_pwd"],
                    authorization_domain=AuthorizationDomainConfig(
                        type=AuthorizationDomainType.LOCAL,
                        authorizations=[AuthorizationConfig("root", AccessLevel.ELEVATED)],
                    ),
                )
            ],
            private_data=[
                DataConfig(owner="root", description="secret data for ex-filtration", id="db"),
                DataConfig(id="/firehole-config.yml", description=file_fh_mysql, owner="root"),
                DataConfig(id="/entrypoints/entrypoint-x-db-fix.sh", description=db_fix, owner="root"),
            ],
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress(network_public.first + 11), network_public)],
    shell="",
    id="node_wordpress_database",
)

node_vsftpd = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            name="vsftpd",
            owner="root",
            version="2.3.4",
            local=False,
            access_level=AccessLevel.LIMITED,
            private_data=[
                DataConfig(id="/firehole-config.yml", description=file_fh_vsftpd, owner="root")
            ]
        )
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress(network_server.first + 11), network_server)],
    shell="",
    id="node_vsftpd",
)

node_workstation = NodeConfig(
    active_services=[],
    passive_services=[
        PassiveServiceConfig(
            name="samba",
            owner="root",
            version="3.5.2",
            local=False,
            access_level=AccessLevel.ELEVATED,
            parameters=[
                (ServiceParameter.ENABLE_SESSION, True),
                (ServiceParameter.SESSION_ACCESS_LEVEL, AccessLevel.ELEVATED),
            ],
            authentication_providers=[auth_local_password("user_pc_pwd")],
            access_schemes=[
                AccessSchemeConfig(
                    authentication_providers=["user_pc_pwd"],
                    authorization_domain=AuthorizationDomainConfig(
                        type=AuthorizationDomainType.LOCAL,
                        authorizations=[AuthorizationConfig("root", AccessLevel.ELEVATED)],
                    ),
                ),
            ],
            private_data=[
                DataConfig(id="/firehole-config.yml", description=file_fh_smb, owner="root")
            ]
        ),
    ],
    traffic_processors=[],
    interfaces=[InterfaceConfig(IPAddress(network_internal.first + 11), network_internal)],
    shell="",
    id="node_workstation",
)

# -----------------------------------------------------------------------------
# Router definitions
# -----------------------------------------------------------------------------
router_perimeter = RouterConfig(
    interfaces=[
        InterfaceConfig(IPAddress(network_internal.first + 1), network_internal, index=0),
        InterfaceConfig(IPAddress(network_public.first + 1), network_public, index=1),
        InterfaceConfig(IPAddress(network_public.first + 1), network_public, index=2),
        InterfaceConfig(IPAddress(network_outside.first + 1), network_outside, index=3),
        InterfaceConfig(IPAddress(network_outside.first + 1), network_outside, index=4),
    ],
    traffic_processors=[
        FirewallConfig(
            default_policy=FirewallPolicy.ALLOW,
            chains=[
                FirewallChainConfig(
                    type=FirewallChainType.FORWARD,
                    policy=FirewallPolicy.ALLOW,
                    rules=[],
                )
            ],
        )
    ],
    routing_table=[RouteConfig(network_internal, 0)],
    id="perimeter_router",
)

router_internal = RouterConfig(
    interfaces=[
        InterfaceConfig(IPAddress(network_server.first + 1), network_server, index=0),
        InterfaceConfig(IPAddress(network_internal.first + 1), network_internal, index=1),
        InterfaceConfig(IPAddress(network_internal.first + 1), network_internal, index=2),
    ],
    traffic_processors=[
        FirewallConfig(
            default_policy=FirewallPolicy.DENY,
            chains=[
                FirewallChainConfig(
                    type=FirewallChainType.FORWARD,
                    policy=FirewallPolicy.DENY,
                    rules=[
                        FirewallRule(
                            src_net=network_internal, dst_net=network_internal, service="*", policy=FirewallPolicy.ALLOW
                        ),
                        FirewallRule(
                            src_net=network_internal, dst_net=network_public, service="*", policy=FirewallPolicy.ALLOW
                        ),
                        FirewallRule(
                            src_net=network_public, dst_net=network_internal, service="*", policy=FirewallPolicy.ALLOW
                        ),
                        FirewallRule(
                            src_net=network_internal, dst_net=network_server, service="*", policy=FirewallPolicy.ALLOW
                        ),
                        FirewallRule(
                            src_net=network_server, dst_net=network_internal, service="*", policy=FirewallPolicy.ALLOW
                        ),
                    ],
                )
            ],
        )
    ],
    routing_table=[
        RouteConfig(network_public, 1),
        RouteConfig(network_server, 0),
    ],
    id="internal_router",
)

router_server = RouterConfig(
    interfaces=[
        InterfaceConfig(IPAddress(network_server.first + 1), network_server, index=0),
        InterfaceConfig(IPAddress(network_server.first + 1), network_server, index=1),
    ],
    traffic_processors=[
        FirewallConfig(
            default_policy=FirewallPolicy.DENY,
            chains=[
                FirewallChainConfig(
                    type=FirewallChainType.FORWARD,
                    policy=FirewallPolicy.DENY,
                    rules=[
                        FirewallRule(
                            src_net=network_server, dst_net=network_server, service="*", policy=FirewallPolicy.ALLOW
                        ),
                        FirewallRule(
                            src_net=network_server, dst_net=network_internal, service="*", policy=FirewallPolicy.ALLOW
                        ),
                        FirewallRule(
                            src_net=network_internal, dst_net=network_server, service="*", policy=FirewallPolicy.ALLOW
                        ),
                    ],
                )
            ],
        )
    ],
    routing_table=[
        RouteConfig(network_internal, 0),
    ],
    id="server_router",
)

# -----------------------------------------------------------------------------
# Connection definitions
# -----------------------------------------------------------------------------
connections_perimeter_router = [
    ConnectionConfig(node_attacker, 0, router_perimeter, 3),
    ConnectionConfig(node_dns, 0, router_perimeter, 4),
    ConnectionConfig(node_wordpress, 0, router_perimeter, 1),
    ConnectionConfig(node_database, 0, router_perimeter, 2),
]

connections_internal_router = [
    ConnectionConfig(node_workstation, 0, router_internal, 2),
]

connections_server_router = [
    ConnectionConfig(node_vsftpd, 0, router_server, 1),
]

connections_routes = [
    ConnectionConfig(router_perimeter, 0, router_internal, 1),
    ConnectionConfig(router_internal, 0, router_server, 0),
]

# -----------------------------------------------------------------------------
# Exploit definitions
# -----------------------------------------------------------------------------
exploit_wordpress = ExploitConfig(
    [VulnerableServiceConfig("wordpress", "6.1.1", "6.1.1")],
    ExploitLocality.REMOTE,
    ExploitCategory.AUTH_MANIPULATION,
)

exploit_mysql = ExploitConfig(
    [VulnerableServiceConfig("mysql", "8.0.31", "8.0.31")],
    ExploitLocality.REMOTE,
    ExploitCategory.CODE_EXECUTION,
)

exploit_vsftpd = ExploitConfig(
    [VulnerableServiceConfig("vsftpd", "2.3.4", "2.3.4")],
    ExploitLocality.REMOTE,
    ExploitCategory.AUTH_MANIPULATION,
)

exploit_smb = ExploitConfig(
    [VulnerableServiceConfig("samba", "3.5.2", "3.5.2")],
    ExploitLocality.REMOTE,
    ExploitCategory.AUTH_MANIPULATION,
)

# -----------------------------------------------------------------------------
# Packaging it together
# -----------------------------------------------------------------------------
nodes = [
    node_attacker,
    node_dns,
    node_wordpress,
    node_database,
    node_vsftpd,
    node_workstation,
]
routers = [router_perimeter, router_internal, router_server]
connections = [*connections_perimeter_router, *connections_internal_router, *connections_server_router, *connections_routes]
exploits = [exploit_wordpress, exploit_mysql, exploit_vsftpd, exploit_smb]
all_config_items = [*nodes, *routers, *connections, *exploits]
