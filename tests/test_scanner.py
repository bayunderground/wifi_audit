
from audit.scanner import parse_scan,filter_access_points

sample="""BSS aa:bb:cc:dd:ee:ff(on wlan1)
    signal: -44.00 dBm
    DS Parameter set: channel 6
    SSID: TP-Link_Main
    RSN:
BSS 11:22:33:44:55:66(on wlan1)
    signal: -70.00 dBm
    DS Parameter set: channel 11
    SSID: TP-Link_TestSN
    RSN:
"""
aps=parse_scan(sample)
assert len(aps)==2
assert aps[0].essid=="TP-Link_Main"
assert aps[0].encryption=="WPA2-PSK"
f=filter_access_points(aps,r"^TP-Link_.*",r"^TP-Link_.*SN$")
assert len(f)==1
assert f[0].essid=="TP-Link_Main"
