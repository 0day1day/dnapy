#!/usr/local/bin/python2.6
#
# DERPY 1.0
# (c) Gregory Price, 2011
# 
# DERPY is a DNS Analysis tool with various extentions
#   Hooves  : Domain name structure analysis (# of vowels, # of numerical chars, character frequency analysis)
#   Dash    : Time Based Analysis
#   Jack    : Answer Based Analysis
#   Blips   : BLIPs support integrated in.  For details, see BLIPs documentation
#

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
    config_file     = open('gmprice/derpy/wip/settings.ini')
    #config_file     = open('gmprice/derpy/settings.ini')
    raws,settings   = config_file.readlines(), {}
    must_haves      = ['blips','hooves','jack','dash','rainbow','fusion','agent_dir']
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
                print 'agent_dir not defined in derpy.ini, cannot open agents\r\nExiting'
                raise
            else:
                settings[i] = False
except:
    print 'derpy.ini file format issue, please check derpy.ini for errors'
    print 'format:\n\tblips=On\n\thooves=On\n\tjack=Off\n\tdash=Off\n\tagent_dir=/path/to/agents/'
    sys.exit()

print "[Derpy] Current Settings:"
for i in settings:
    print "\t%s:\t%s" %(i,settings[i])



#####################################################
#                  Power Class                      #
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
#    Also implemented DNS blips here so we're not   #
#                 double-parsing DNS                #
#          ########### END NOTE #############       #
#####################################################

class power(list):
    def __init__(self,iq,oq):
        # general resources
        self.starttime          =   time.time()                     # The Time Power was started
        self.in_queue           =   iq                              # Overall in queue used for collection
        self.out_queue          =   oq

        # Intialize blips, if settings has blips support on, we're gonna use blips here rather than elsewhere
        if settings['blips'] == 'On':
            import blips
            self.DOMAIN_TREE    =   blips.tree()
            self.blip           =   self.DOMAIN_TREE.domain_search
            self.blipip         =   self.DOMAIN_TREE.ip_search
            self.blips_out      =   self.out_queue                  # used for reporting

        # Initiate Derpy Dash (time features) 
        if settings['dash'] == 'On':
            import dash
            self.icq            =   Queue()
            self.dash           =   Process(target=dash.dash,    
                                            args=(self.icq,self.out_queue,self.starttime,settings))
            self.dash.start()
        
        # Initiate Derpy Jack (answer features)
        if settings['jack'] == 'On':
            import jack
            self.iaq            =   Queue()
            self.jack           =   Process(target=jack.jack,
                                            args=(self.iaq,self.out_queue,self.starttime,settings))
            self.jack.start()

        # Initiate Derpy Hooves
        if settings['hooves'] == 'On':
            import hooves
            self.inq            =   Queue()
            self.hooves         =   Process(target=hooves.hooves,
                                            args=(self.inq,self.out_queue,self.starttime,settings))
            self.hooves.start()                                     # start it up!
        
        # Initiate Rainbow Love (reporting process), pass all OUT queues (o_q), then start it
        if settings['rainbow'] == 'On':
            import rainbow
            self.rainbow_love   =   Process(target=rainbow.rainbow_love, args=(self.out_queue,self.starttime,settings))
            self.rainbow_love.start()
        else:
            print '################### WARNING ####################'
            print 'RAINBOW LOVE IS OFF, NO ALERTS WILL BE GENERATED'
            print '################### WARNING ####################'
        
        self.run()                                                  # Lets get it on!


    def run(self):
        # receive data and send for analysis
        print '[%s] [Power] Running' %(time.ctime())
        sleeps = 0
        while 1:
            try:
                k = self.in_queue.qsize()
                meta,data = self.in_queue.get_nowait()  # if something in queue, get it
                self.analyze(meta,dns.DNS(data))        # then analyze it
            except:                                 # if nothing in queue sleep .5 sec
                #print '[%s] [Power] Error - Queue Size: %s' %(time.ctime(),k)
                sleeps += .5                        # this prevents resource hogging
                time.sleep(.5)
            if sleeps > 300 and settings['blips'] == 'On':  # every 5 slept minutes, update blips
                print '[%s] [Power] Checking for blips updates' %(time.ctime())
                self.DOMAIN_TREE.update()
                sleeps = 0


    def analyze(self,meta,data): # Analyze the DNS packet, handle distribution to agents.
        # Meta = [metadata list format]
        # Data is a dpkt.dns object
        try:
            if data.opcode == dns.DNS_QUERY:
                # operation is Query or Query Response
                # DNS Query Analysis
                if data.qr == dns.DNS_Q:
                    doms = {}
                    for i in xrange(len(data.qd)): # for domain in query list
                        try:
                            name = domaintools.tld_detect(data.qd[i].name))
                            if settings['blips'] == 'On':
                                res = self.blip(name[2])
                            else:
                                res = {'white':False,'hard':False}
                            if name:
                                if not (res['white'] and res['hard']):
                                    # put [meta,name,'Q'] into derpy.hooves queue ('Q' = query)
                                    if settings['hooves'] == 'On':
                                        self.inq.put([meta,name,'Q'])
                                    # put meta and domain into derpy.dash queue
                                    if settings['dash'] == 'On':
                                        self.icq.put([meta,name])
                                # Blips support goes here
                                if settings['blips'] == 'On' and name[2] not in doms:
                                    report = {  'type'  :'event','agent' :'blips',
                                                'event' :{'agent' :'blips','meta':meta, 'res':res, 'host':name[2]}}
                                    if settings['rainbow']: self.out_queue.put(report)
                                    doms[name[2]] = ''
                        except: pass
                # DNS Response analysis
                elif data.qr == dns.DNS_R:
                    ips,doms = {},{}
                    for i in xrange(len(data.an)):  # cycle through answers
                        if data.an[i].cls == dns.DNS_IN:
                            if data.an[i].type == dns.DNS_A:
                                # if answers, answer(ip) and ttl analysis
                                try:
                                    name = domaintools.tld_detect(data.an[i].name)
                                    if settings['blips'] == 'On':
                                        res = self.blip(name[2])
                                    else:
                                        res = {'white':False,'hard':False}
                                    if name:
                                        ip, ttl = data.an[i].ip, data.an[i].ttl
                                        if settings['jack'] == 'On':
                                            self.iaq.put([meta,data.an[i].name,ip,'R',ttl])
                                        if not (res['white'] and res['hard']):
                                            # blips ip support goes here
                                            if settings['blips'] == 'On':
                                                ires = self.blipip(ip)
                                                if not ires['white'] and ires['hard'] and ip not in ips:
                                                    ires['msg'] = 'Domain Resolution Contained Blacklisted IP Address'
                                                    report = {  'type'  :'event','agent' :'blips',
                                                                'event' :{'agent' :'blips','meta':meta, 'res':ires, 'host':dec2ip(unpack('>I',ip)[0])}}
                                                    if settings['rainbow']: self.out_queue.put(report)
                                                    ips[ip] = ''
                                        if settings['blips'] == 'On' and name[2] not in doms:
                                            report = {  'type'  :'event','agent' :'blips',
                                                        'event' :{'agent' :'blips','meta':meta, 'res':res, 'host':name[2]}}
                                            if settings['rainbow']: self.out_queue.put(report)
                                            doms[name[2]] = ''
                                                
                                except: pass 
                            elif data.an[i].type == dns.DNS_CNAME:
                                # if this is in alias, answer(alias) analysis
                                try:
                                    name    = domaintools.tld_detect(data.an[i].name)
                                    cname   = domaintools.tld_detect(data.an[i].cname)
                                    res     = self.blip(cname[2])
                                    if (name and cname) and (data.an[i].name != data.an[i].cname):
                                        if settings['jack'] == 'On':
                                            self.iaq.put([meta,data.an[i].name,data.an[i].cname,'A'])
                                        if res['white'] and res1['hard']:
                                            pass
                                        else:
                                            # [meta,cname,'A'] name analysis ('A'=alias)
                                            if settings['hooves'] == 'On':
                                                self.inq.put([meta,cname,'A'])                                    
                                except: pass
        except: pass


if __name__ == '__main__':
    print 'Testing build (starts power as new process, runs test pcap, then exits'
    settings['rainbow'] == 'Off'
    dp = Process(target=power,args=((Queue(),Queue())))
    dp.start()
    # hardcode pcap here
    time.sleep(60)
    print 'Exiting'
    sys.exit()

# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class
