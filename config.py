# -----------------------------------------------------------------------------
# CORE CONFIGURATION & CONSTANTS
# -----------------------------------------------------------------------------

class Config:
    BANNER = r"""
 ██╗    ██╗██╗███████╗██╗    ████████╗ ██████╗  ██████╗ ██╗      ██╗  ██╗██╗████████╗
 ██║    ██║██║██╔════╝██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║      ██║ ██╔╝██║╚══██╔══╝
 ██║ █╗ ██║██║█████╗  ██║       ██║   ██║   ██║██║   ██║██║      █████╔╝ ██║   ██║   
 ██║███╗██║██║██╔══╝  ██║       ██║   ██║   ██║██║   ██║██║      ██╔═██╗ ██║   ██║   
 ╚███╔███╔╝██║██║     ██║       ██║   ╚██████╔╝╚██████╔╝███████╗ ██║  ██╗██║   ██║   
  ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝ ╚═╝  ╚═╝╚═╝   ╚═╝  
                     [ 802.11 Wireless Audit Framework ]
    """
    # Formulae :- 2407 + (5 * channel)
    _2GHZ = {i: 2412 + (i - 1) * 5 for i in range(1, 14)}

    # Channel 14 is restricted in all contries except for Japan
    # since channel 13 is 2472, applying formulae 2412 + (5 * 13) = 2477 (invalid freq)
    # hence, we make sure the _2GHZ's key '14' is 2484
    _2GHZ[14] = 2484

    # 5GHz channels (inconsistent freq range, hence, need to hardcode)
    _5GHZ = {
        36: 5180, 40: 5200, 44: 5220, 48: 5240, 52: 5260, 56: 5280, 60: 5300, 64: 5320,
        100: 5500, 104: 5520, 108: 5540, 112: 5560, 116: 5580, 120: 5600, 124: 5620,
        128: 5640, 132: 5660, 136: 5680, 140: 5700, 144: 5720, 149: 5745, 153: 5765,
        157: 5785, 161: 5805, 165: 5825, 169: 5845, 173: 5865, 177: 5885,
    }

    IFTYPE_NAMES = {
        0: 'UNSPECIFIED', 1: 'AD HOC', 2: 'STATION', 3: 'AP', 4: 'AP_VLAN',
        5: 'WDS', 6: 'MONITOR', 7: 'MESH POINT', 8: 'P2P CLIENT', 9: 'P2P GO',
        10: 'P2P DEVICE', 11: 'OCB', 12: 'NAN'
    }

    MODE_DESCRIPTIONS = {
        'adhoc': 'AD-HOC', 'ibss': 'AD-HOC', 'ap': 'Access Point',
        'ap_vlan': 'Access Point (VLAN)', 'monitor': 'Monitor (Sniffer)',
        'mesh_point': 'Mesh Point', 'p2p_client': 'P2P Client',
        'p2p_go': 'P2P Group Owner', 'station': 'Regular Client Mode',
    }
