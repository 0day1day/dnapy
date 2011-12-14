#!/usr/local/bin/python2.6
#
# DERPY 1.0
# (c) Gregory Price, 2011
# 
# DERPY is a DNS Analysis tool with various extentions
#   Jack    : Answer Based Analysis
#

import sys, time
from struct import unpack
from os import popen
sys.path.append('/projectawesome_live/projectawesome/generic_imports/')
from dbhandle import *
from ipconvert import dec2ip

###################################################
#                  Jack Class                     #
#             Answer-Based Features               #
###################################################

class jack(list):
    def __init__(self,iaq,oaq,started,setcopy):
        # Queues
        self.in_queue   = iaq
        self.out_queue  = oaq

        # Settings
        self.settings = setcopy
        self.setup(setcopy)

        # Timing and other parameters
        self.stime  = started   # time started, or since last analysis
        self.t_int  = 900       # analysis interval - 15 minutes
        #self.t_int  = 150
        #self.t_int  = 30

        # analysis settings
        self.depth  = 1         # depth of correlation (domain->ip->domain->ip... etc)

        # History Structure: {ips:{ip:storage},domains:{domain:storage}}
        self.hist   = {'ips':{},'domains':{}}
        self.events = {}

        # Lets begin!
        self.start()


    def setup(self,dsets):
        # read the settings file and set the threshholds
        pass


    class storage(list):
        def __init__(self,name):
            self.name   = name  # the name of what is being stored (the domain or ip)
            self.dom    = {}    # domain:hits
            self.ips    = {}    # ip    :hits
            self.ttl    = {}    # ttl   :hits
            self.alias  = {}    # alias :hits
            self.geo    = ''    # for ip tree only, geolocation of that ip


    def start(self):
        print '[%s] [Jack] Running' %(time.ctime())
        while 1:
            try: # Get events from the queue
                qsize = self.in_queue.qsize()
                inp = self.in_queue.get_nowait()
                if inp[3] == 'R': # Resolution Type
                    meta, name, ip, type, ttl = inp
                    self.add_hits(meta,name,ip,type,ttl)
                elif inp[3] == 'A': # Alias Type
                    meta, name, cname, type = inp
                    self.add_hits(meta,name,cname,type,0)
                else:
                    print inp[3]
            except: # If no events or error, sleep .5
                time.sleep(.5)
                #print 'Error: Queue Size - %s' %(qsize)

            # Time check for local and global update goes here
            if (time.time()-self.stime) > self.t_int:
                print '[%s] [Jack] Saving Tickle Data' %(time.ctime())
                self.stime += self.t_int    # Add interval to current time
                self.save()                 # Saves map information to database for fusion and tickle use
                #self.analyze()             # don't do analysis

                # update Rainbow Love
                if self.settings['rainbow'] == 'On' and self.settings['fusion'] == 'On':
                    print '[%s] [Jack] Updating Rainbow Love' %(time.ctime())
                    report = {  'type':'agent', 'agent':'Jack',
                                'event':{'hist':self.hist,'new':self.events}}
                    self.out_queue.put(report)    # send update to Rainbow Love

                del self.hist['domains']; self.hist['domains'] = {}


    def add_hits(self, meta, name, res, type, ttl):
        # Add packet attributes to the history

        # Normal resolution response: IPs, domains, TTLs
        if type == 'R':
            # First add ip & domain to 'ips'
            if res in self.hist['ips']: 
                curip = self.hist['ips'][res]       # Check if IP exists in history
                if name in curip.dom:                            # if yes...
                    curip.dom[name] += 1            # +1 to domain hit
                else: 
                    curip.dom[name] = 1             # or add domain
            else:                                               # If no...
                ts = self.storage(res)              # create new info retainer
                ts.dom[name] = 1                    # Set hits to 1
                cmd = 'geoiplookup '+dec2ip(unpack('>I',res)[0])   # Do GeoIPLookup
                ts.geo = popen(cmd).read().split(': ')[1].rstrip() # Set geolocation to results
                self.hist['ips'][res] = ts          # store into history
            # Now add ip and ttl to 'domains'
            if name in self.hist['domains']:
                curdom = self.hist['domains'][name] # Check if domain exists in history
                if res in curdom.ips:               # if yes...
                    curdom.ips[res] += 1                # +1 to ip hit
                else: 
                    curdom.ips[res] = 1                 # or add ip
                if ttl in curdom.ttl:    
                    curdom.ttl[ttl] += 1                # +1 to distinct ttl
                else:
                    curdom.ttl[ttl] = 1                 # or add new distinct ttl
                if name in curdom.dom:    
                    curdom.dom[name] += 1               # +1 to domain hits
                else: 
                    curdom.dom[name] = 1                # or add domain
            else:                               # if no...
                tdom = self.storage(name)               # create new retainer
                tdom.ips[res] = 1                       # add ip
                tdom.ttl[ttl] = 1                       # add ttl
                self.hist['domains'][tdom.name] = tdom  # save to history
        # Alias Responses:  Domain & Alias additions/incrimentations
        elif type == 'A':   # For response type w/ alias
            if name in self.hist['domains']:
                curdom = self.hist['domains'][name]     # Check if domain exists
                if res in curdom.alias:                     # If yes...
                    curdom.alias[res] += 1              # +1 to distinct alias
                else:
                    curdom.alias[res] = 1               # or add new distinct alias
            else:                                           # If no...
                tdom = self.storage(name)               # create new retainer
                tdom.alias[res] = 1                     # add new alias
                self.hist['domains'][tdom.name] = tdom  # save to history


    def save(self):
        dbopen()                                        # make sure we open the database :3
        bulks = []
        for dom in self.hist['domains']:                # for each domain in self.hist
            curdom = self.hist['domains'][dom]
            dbinsert("insert ignore into tickle.hosts2 (host_name) values ('%s')" %(dom))              # insert into domains table
            hid = dbsearch("select host_id from tickle.hosts2 where host_name = '%s'" %(dom))[0][0]  # Get host_id for insertion
            for ip in curdom.ips:                       # for each ip that domain resolved to
                # insert into resolutions table or +hits
                bulks.append("insert into tickle.resolutions2 (type_id,host_id,ip_addr,seen_first,seen_last,hits) values ('%s','%s','%s','%s','%s','%s') on duplicate key update seen_last = values(seen_last), hits = hits+values(hits)" %(1,hid,unpack('>I',ip)[0],int(time.time()),int(time.time()),curdom.ips[ip]))
            
            for alias in curdom.alias:                  # for each alias returned
                dbinsert("insert ignore into tickle.hosts2 (host_name) values ('%s')" %(alias))                     # insert alias into domain table
                aid = dbsearch("select host_id from tickle.hosts2 where host_name = '%s'" %(dom))[0][0]  # get host_id for that insertion
                bulks.append("insert ignore into tickle.alias (host_id,alias_id) values ('%s','%s')" %(hid,aid))    # insert domain:alias into alias table

            for ttl in curdom.ttl:                      # for each ttl returned
                bulks.append("insert into tickle.ttl (host_id,ttl,hits) values ('%s','%s','%s') on duplicate key update hits = hits+values(hits)" %(hid,ttl,curdom.ttl[ttl]))
        for i in xrange(0,len(bulks),1000):             # insert 1000 at a time
            dbbulkinsert(bulks[i:i+999])
        print '[%s] [Jack] Completed bulk inserts and deleted history' %(time.ctime())


# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class
