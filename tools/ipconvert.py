# Converts Dotted Decimal ip to Decimal, and visa-versa

from socket import inet_aton, inet_ntoa
from struct import unpack, pack

### Dotted Decimal to Decimal IP Conversion ###
def ip2dec(IP):
    if IP:
        dec = unpack('>I',inet_aton(IP))[0]
        return dec
    else:
        return ''

### Decimal to Dotted Decimal IP Conversion ###
def dec2ip(dec):
    if dec:
        ip = inet_ntoa(pack(">I",dec))
        return ip
    else:
        return ''

# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class
