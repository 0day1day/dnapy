#!/usr/local/bin/python2.6
#
# DERPY 1.0
# (c) Gregory Price, 2011
# 
# DERPY is a DNS Analysis tool with various extentions
#   Rainbow : Reporting and Fusion Analysis Agent - Probably going to split this up into two separate processes
#

import sys, re, time, laso
sys.path.append('/investigations/gmprice/generic_imports/')
from dbhandle import *
import domaintools

##############################################
#       Non-Malicious Domain Reporting       #
##############################################

ceflog = open('/investigations/tools/ti-Carp/logs/ticarp.cef','a')
def writecef(vendor,sig,hostname,priority,extension):
    ceflog.write("CEF:0|%s|TiCarp|2.0|%s|%s|%s|%s" %(vendor,sig,hostname,priority,extension))
    ceflog.flush()


###################################################
#               Rainbow_Love Class                #
#       Global Analysis & Reporting Module        #
###################################################

class rainbow_love(list):
    #def __init__(self,out_queues,starttime):
    def __init__(self,iq,starttime,setcopy):
        # first initial our laso connection
        self.aip        =   laso.laso()
        self.aip_setup()

        # Setup Rainbow's Settings
        self.settings = setcopy
        self.rainbow_setup()
        
        # Define the Input Queue
        self.in_queue = iq

        # Various Parameters
        self.time       =   starttime
        self.loops      =   0
        self.events     =   {}
        self.untickled  =   {}
        self.updated    =   0
        self.get_updates()


    def aip_setup(self):
        # Handles initial connection with AIP
        if self.aip.login("derpy","MLP:FIM"):   # Login
            self.aip.vendor("Derpy")            # Set Vendor
            self.aip.version("1.0")             # Set Version
            print "[%s] [Rainbow Love] AIP connection established." %(time.ctime())
        else:                                   # If failure to Login
            self.aip.bye()                      # Say bye
            print "[%s] [Rainbow Love] Could not start aip connector." %(time.ctime())
            print "[%s] [Rainbow Love] Shutting down." %(time.ctime())
            sys.exit()                          # Shutdown
        pass


    def aip_shutdown(self):
        # Shut down aip connection and exit
        print '[%s] [Rainbow Love] Shutting down AIP.' %(time.ctime())
        self.aip.bye()
        print '[%s] [Rainbow Love] Shutting down self.' %(time.ctim())
        sys.exit()

    
    def rainbow_setup(self):
        # First figure out which agents are running so we can handle fusion properly
        self.derps = 0
        if self.settings['dash']:    self.derps += 1
        if self.settings['hooves']:  self.derps += 1
        if self.settings['jack']:    self.derps += 1

        # Next open the settings file, and read it in.
        pass


    def get_updates(self):
        # Get events and reports from each agent
        # Report:   Information to be used in fusion analysis
        # Event:    Agent Individually detected something suspicious and wants to report it
        print "[%s] [Rainbow Love] Waiting for events." %(time.ctime())
        while 1:
            #for queue in self.queues:                               # round robin through each queue
            #while (time.time()-self.time) < 900 and self.updated != self.derps:
            for i in xrange(10000):
                try:
                    eventdict = self.in_queue.get_nowait()
                    # Handle Reports
                    if eventdict['type'] == 'agent':
                        print '[%s] [Rainbow Love] %s updating...' %(time.ctime(), eventdict['agent'])
                        self.events[eventdict['agent']] = eventdict['events']
                        self.updated += 1

                    # Handle Events
                    elif eventdict['type'] == 'event':
                        self.alert(eventdict['event'])  # report the event
                except:
                    time.sleep(.5)

            # if all 3 agents have reported, and it's been a set interval
            if self.derps and (time.time()-self.time) > 900 and self.updated == self.derps:
                self.time += 900
                self.loops   += 1       # Record how many time intervals 
                if self.settings['tickle'] == 'On':
                    self.tickle()
                if self.settings['fusion'] == 'On':
                    self.analyze()      # Do fusion analysis
                self.updated = 0        # Reset agent report record
                self.events  = {}       # clear the events dictionary
            elif not self.derps:
                self.events = {}

            # Test the AIP connection to ensure we still have reporting available
            if self.aip.ping() != -1:
                pass                # not -1, it's open and clear
            else:
                print '[%s] [Rainbow Love] AIP Connection Error.' %(time.ctime())
                self.aip_shutdown() # otherwise we have a problem, shutdown!


    def tickle(self):
        # combine agent data into tickle information and save it to the database
        dbopen()                                        # make sure we open the database :3
        bulks = []
        for dom in self.events['Jack']['hist']['domains']:                # for each domain in self.hist
            #################################################################
            #                     Get Hooves Score Here                     #
            #       If hooves score not present, save it for next time      #
            #################################################################
            curdom = self.events['Jack']['hist']['domains'][dom]
            dlvl = domaintools.tld_detect(dom)[2]
            if dlvl not in self.events['Hooves']['hist']:
                hscore = 0
            else:
                hscore = self.events['Hooves']['hist'][dlvl]['score']
            
            dbinsert("insert into tickle.hosts2 (host_name,score) values ('%s','%s') on duplicate key update score = values(score)" %(dom,hscore))              # insert into domains table
            hid = dbsearch("select host_id from tickle.hosts2 where host_name = '%s'" %(dom))[0][0]  # Get host_id for insertion
            for ip in curdom.ips:                       # for each ip that domain resolved to
                # insert into resolutions table or +hits
                bulks.append("insert into tickle.resolutions2 (type_id,host_id,ip_addr,seen_first,seen_last,hits) values ('%s','%s','%s','%s','%s','%s') on duplicate key update seen_last = values(seen_last), hits = hits+values(hits)" %(1,hid,unpack('>I',ip)[0],int(time.time()),int(time.time()),curdom.ips[ip]))

            for alias in curdom.alias:                  # for each alias returned
                alvl = domaintools.tld_detect(alias)[2]
                if alvl in self.events['Hooves']['hist'][dom]['score']:
                    ahscore = self.events['Hooves']['hist'][dom]['score'][alvl]
                else:
                    ahscore = 0
                dbinsert("insert into tickle.hosts2 (host_name,score) values ('%s','%s') on duplicate key update score = values(score)" %(alias,ahscore))
                aid = dbsearch("select host_id from tickle.hosts2 where host_name = '%s'" %(dom))[0][0]  # get host_id for that insertion
                bulks.append("insert ignore into tickle.alias (host_id,alias_id) values ('%s','%s')" %(hid,aid))    # insert domain:alias into alias table

            for ttl in curdom.ttl:                      # for each ttl returned
                bulks.append("insert into tickle.ttl (host_id,ttl,hits) values ('%s','%s','%s') on duplicate key update hits = hits+values(hits)" %(hid,ttl,curdom.ttl[ttl]))
        for i in xrange(0,len(bulks),1000):             # insert 1000 at a time
            dbbulkinsert(bulks[i:i+999])

        del self.hist['domains']; self.hist['domains'] = {}
        print '[%s] [Rainbow] Completed Tickle Inserts' %(time.ctime())


    def analyze(self):
        #global picture analysis, can output new events, primary features is reports
        pass


    def alert(self,event):
        # set aip program to the agent name
        program = event['agent']
        version = '1.0'

        meta = event['meta']

        # set main cef parameters
        if event['agent'] == 'blips':   # handle blips event
            program = 'Blips'
            bevent = event['res']
            if 'Blacklisted' not in bevent['msg'] or bevent['partial']:
                vendor = 'CNOC-Tuning'
            else:
                vendor = 'CNOC'
            eName   = event['host']
            sigID   = bevent['sigs']
            priority= bevent['priority']
            if meta[1] == 53:
                msg = 'DNS '+bevent['msg']+' Resolution'
            elif meta[3] == 53: 
                msg = 'DNS '+bevent['msg']+' Request'
            elif meta[1] == 80 or meta[3] == 80: 
                msg = 'HTTP '+bevent['msg']+' Request'
            elif meta[1] == 443 or meta[3] == 443:
                msg = 'HTTP over SSL '+bevent['msg']+' Request'
            else:
                msg = 'Non-Standard Port '+bevent['msg']+' Request'
            if bevent['sigs']:
                msg = msg + ' : '+bevent['sigs']
        else:                           # handle all others
            vendor = 'Derpy'
            eName   = event['host']
            sigID   = event['sig']
            priority= event['lvl']
            msg     = event['msg']

        if meta[4] == 6:
            proto = 'TCP'
        else:
            proto = 'UDP'
        extension = "end="+str(meta[5])     +\
                    " src="+meta[0]         +\
                    " spt="+str(meta[1])    +\
                    " dst="+meta[2]         +\
                    " dpt="+str(meta[3])    +\
                    " proto="+proto         +\
                    " cs2=issr"             +\
                    " msg="+msg
        #send to aip to alert to arcsite

        if not sigID: sigID = 'None'

        if vendor == 'CNOC-Tuning':
            ceflog.write("CEF:0|%s|TiCarp|2.0|%s|%s|%s|%s\n" %(vendor,sigID,eName,priority,extension))
            ceflog.flush()
        elif "Suspicious Top Level Domain" not in msg and not re.search('[_/\?\&]',eName):
            if self.aip.rawEvent(vendor, program, version, sigID, eName, priority, extension) == -1: # Ensure there are no errors
                print '[%s] [Rainbow Love] Failed to log event (%s)\n' %(time.ctime(),str(self.aip.last_error))

    def report(self):
        # writes a report if fusion analysis finds something
        pass

# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class
