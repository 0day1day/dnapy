#!/usr/local/bin/python2.6


import sys, re, time
from dpkt import dns
from struct import unpack
from multiprocessing import Process, Queue
sys.path.append('gmprice/generic_imports/')
from dbhandle import *
from ipconvert import dec2ip
import domaintools

##############################################
#       Load the Configuration File          #
##############################################
try:
    config_file     = open('settings.ini')
    raws,settings   = config_file.readlines(), {}
    must_haves      = ['known_domains','name_structure','dns_answer','time_analysis','reporting','fusion','agent_dir']
    for i in raws:
        if i.startswith('#') or not i:
            continue
        j = i.split('=')
        if j[1].rstrip().lstrip() == 'Off':
            j[1] = 'Off'
        elif j[1].rstrip().lstrip() == 'On':
            j[1] = 'On'
        elif j[0] == 'agent_dir':
            j[1] = j[1].rstrip().lstrip()
            if not j[1].endswith('/'): j[1] = j[1]+'/'
            sys.path.append(j[1])
        else:
            print 'Unknown Setting or Value found in Settings file - %s : %s' %(j[0],j[1])
            raise
        settings[j[0].rstrip().lstrip()] = j[1]
    for i in must_haves:
        if i not in settings:
            if i == 'agent_dir':
                print 'agent_dir not defined in settings.ini, cannot open agents\r\nExiting'
                raise
            else:
                settings[i] = False
except:
    print 'dnadns settings file format issue, please check settings.ini for errors'
    sys.exit()

print "[DNS] Current Settings:"
for i in settings:
    print "\t%s:\t%s" %(i,settings[i])



#####################################################
#                    DNS Parser                     #
#        Accepts various data, parses it out        #
# controls data flow to other portions of the agent #
#                                                   #
#          ############## NOTE ##############       #
# multiprocessing.queue() couldn't pickle dpkt.dns  #
# objects (must since we're switching interpreters) #
#                                                   #
#   Solved this problem by passing raw DNS packet   #
#  and using dns.DNS() to convert it after passing  #
#                                                   #
#          ########### END NOTE #############       #
#####################################################

class parser(list):
    def __init__(self,iq,oq):
        # general resources
        self.starttime          =   time.time()                     # The Time parser was started
        self.in_queue           =   iq                              # Overall in queue used for collection
        self.out_queue          =   oq

        # Intialize known domain tools
        if settings['known_domains'] == 'On':
            import knowndomains
            self.DOMAIN_TREE    =   bwlists.tree()
            self.bwdom          =   self.DOMAIN_TREE.domain_search
            self.bwdip 			=   self.DOMAIN_TREE.ip_search
            self.bwlistout      =   self.out_queue                  # used for reporting

        # Initiate Time features
        if settings['time_analysis'] == 'On':
            import timeanalysis
            self.icq            =   Queue()
            self.time           =   Process(target=beacon.beacon,    
                                            args=(self.icq,self.out_queue,self.starttime,settings))
            self.time.start()
        
        # Initiate Answer features
        if settings['dns_answer'] == 'On':
            import dnsanswer
            self.iaq            =   Queue()
            self.answer         =   Process(target=answer.answer,
                                            args=(self.iaq,self.out_queue,self.starttime,settings))
            self.answer.start()

        # Initiate Name Structure features
        if settings['name_structure'] == 'On':
            import nameanalysis
            self.inq            =   Queue()
            self.names	        =   Process(target=name.name,
                                            args=(self.inq,self.out_queue,self.starttime,settings))
            self.namess.start()
        
        # Initiate Reporting process, pass all OUT queues (o_q), then start it
        if settings['reporting'] == 'On':
            import fusion
            self.fusion			=   Process(target=fusion.fusion, 
											args=(self.out_queue,self.starttime,settings))
            self.fusion.start()
        else:
            print '################### WARNING ####################'
            print 'REPORTING IS IS OFF, NO ALERTS WILL BE GENERATED'
            print '################### WARNING ####################'
        
        self.run()                                                  # Lets get it on!


    def run(self):
        # receive data and send for analysis
        print '[%s] [DNS] Running' %(time.ctime())
        sleeps = 0
        while 1:
            try:
                k = self.in_queue.qsize()
                meta,data = self.in_queue.get_nowait()  # if something in queue, get it
                self.analyze(meta,dns.DNS(data))        # then analyze it
				
            except:
                #print '[%s] [DNS] Error - Queue Size: %s' %(time.ctime(),k)
                sleeps += .5                        # this prevents resource hogging
                time.sleep(.5)
				
            if sleeps > 300 and settings['known_domains'] == 'On':  # every 5 slept minutes, update known domain features
                print '[%s] [DNS] Checking for known_domains updates' %(time.ctime())
                self.DOMAIN_TREE.update()
                sleeps = 0


    def analyze(self,meta,data): # Analyze the DNS packet, handle distribution to agents.
        # Meta = [metadata list format]
        # Data is a dpkt.dns object
        try:
            if data.opcode == dns.DNS_QUERY:	# operation is Query or Query Response
				if data.qr == dns.DNS_Q:		# DNS Query Analysis
                    doms = {}
                    for i in xrange(len(data.qd)): # for domain in query list
                        try:
                            name = domaintools.tld_detect(data.qd[i].name))
							
                            if settings['known_domains'] == 'On':
                                res = self.blip(name[2])
                            else:
                                res = {'white':False,'hard':False}
								
                            if name:
                                if not (res['white'] and res['hard']):
                                    
                                    if settings['name_structure'] == 'On':		# send to name structure analysis [meta,name,'Q'] ('Q' = query)
                                        self.inq.put([meta,name,'Q'])
                                    
                                    if settings['time_analysis'] == 'On':				# put meta and domain into time feature analysis queue
                                        self.icq.put([meta,name])
										
                                if settings['known_domains'] == 'On' and name[2] not in doms:
                                    report = {  'type'  :'event','agent' :'known_domains',
                                                'event' :{'agent' :'known_domains','meta':meta, 'res':res, 'host':name[2]}}
                                    
									if settings['fusion']:
										self.out_queue.put(report)
                                    
									doms[name[2]] = ''
                        except:
							pass
                
                elif data.qr == dns.DNS_R:		# DNS Response analysis
                    ips,doms = {},{}
                    for i in xrange(len(data.an)):  # cycle through answers
                        if data.an[i].cls == dns.DNS_IN:
                            if data.an[i].type == dns.DNS_A:
                                try:				# if answers, answer(ip) and ttl analysis
                                    name = domaintools.tld_detect(data.an[i].name)
									
                                    if settings['known_domains'] == 'On':
                                        res = self.blip(name[2])
                                    else:
                                        res = {'white':False,'hard':False}
										
                                    if name:
                                        ip, ttl = data.an[i].ip, data.an[i].ttl
										
                                        if settings['dns_answer'] == 'On':
                                            self.iaq.put([meta,data.an[i].name,ip,'R',ttl])
											
                                        if not (res['white'] and res['hard']):
                                            # known_domains ip support goes here
                                            if settings['known_domains'] == 'On':
                                                ires = self.blipip(ip)
                                                if not ires['white'] and ires['hard'] and ip not in ips:
                                                    ires['msg'] = 'Domain Resolution Contained Blacklisted IP Address'
                                                    report = {  'type'  :'event','agent' :'known_domains',
                                                                'event' :{'agent' :'known_domains','meta':meta, 'res':ires, 'host':dec2ip(unpack('>I',ip)[0])}}
                                                    if settings['fusion']: self.out_queue.put(report)
                                                    ips[ip] = ''
													
                                        if settings['known_domains'] == 'On' and name[2] not in doms:
                                            report = {  'type'  :'event','agent' :'known_domains',
                                                        'event' :{'agent' :'known_domains','meta':meta, 'res':res, 'host':name[2]}}
                                            if settings['fusion']: self.out_queue.put(report)
                                            doms[name[2]] = ''
                                                
                                except: pass 
								
                            elif data.an[i].type == dns.DNS_CNAME:
                                # if this is in alias, answer(alias) analysis
                                try:
                                    name    = domaintools.tld_detect(data.an[i].name)
                                    cname   = domaintools.tld_detect(data.an[i].cname)
                                    res     = self.blip(cname[2])
                                    if (name and cname) and (data.an[i].name != data.an[i].cname):
                                        if settings['dns_answer'] == 'On':
                                            self.iaq.put([meta,data.an[i].name,data.an[i].cname,'A'])
                                        if res['white'] and res1['hard']:
                                            pass
                                        else:
                                            # [meta,cname,'A'] name analysis ('A'=alias)
                                            if settings['name_structure'] == 'On':
                                                self.inq.put([meta,cname,'A'])                                    
                                except: pass
        except: pass


if __name__ == '__main__':
    print 'Testing build (starts dns parser as new process, runs test pcap, then exits'
    settings['fusion'] == 'Off'
    dp = Process(target=parser,args=((Queue(),Queue())))
    dp.start()
    # hardcode pcap here
    time.sleep(60)
    print 'Exiting'
    sys.exit()

# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class
