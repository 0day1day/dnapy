#!/usr/local/bin/python2.6

'''
This is a skinny PCAP parser made primarily for testing.

Its reliance on dpkt means it's not fast enough for production code at a scaled level.
'''

print 'importing everything'
import sys
sys.path.append('tools/')
sys.path.append('protocols/')
sys.path.append('agents/')
from struct import unpack
from ipconvert import dec2ip
import dpkt, pcap, dnadns, time, multiprocessing
print 'starting dnadns'

in_queue = multiprocessing.Queue()
out_queue = multiprocessing.Queue()
dnsparser = multiprocessing.Process(target=dnadns.parser, args=(in_queue,out_queue))
dnsparser.start()

file = open('testfile.pcap')
p = pcap.pcap(file)
nmp = False
print 'Starting pcap parsing @ %s' %(time.ctime())
while 1:
    check = False
    while 1:
        packet = p.next()
        meta = []
		
        if not packet: 
            print 'No more packets @ %s' %(time.ctime())
            nmp = True
            break
			
        try: 
			ip = dpkt.ethernet.Ethernet(packet[1]).ip
        except: 
			continue
			
        try:		# Getting UDP metadata
            udp = ip.udp
            if udp.sport != 53 and udp.dport != 53: 
				continue
            else:
                sport = udp.sport
                dport = udp.dport
				data = udp.data
        except:		# Getting TCP metadata
            try:
                tcp = ip.tcp
                if tcp.sport != 53 and tcp.dport != 53: 
					continue
                else:
                    sport = tcp.sport
                    dport = tcp.dport
					data = tcp.data
                continue		# haven't added tcp dns support yes, so we'll just continue
            except:
                continue
        break
		
    if nmp: break
    meta = [dec2ip(unpack('>I',ip.src)[0]),
            sport,
            dec2ip(unpack('>I',ip.dst)[0]),
            dport,
            ip.p,
            packet[0][0]
            ]

    in_queue.put([meta,udp.data])

# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class
