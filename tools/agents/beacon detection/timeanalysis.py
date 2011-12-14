#!/usr/local/bin/python2.6
#
# DERPY 1.0
# (c) Gregory Price, 2011
# 
# DERPY is a DNS Analysis tool with various extentions
#   Dash    : Time Based Analysis
#

import sys, time 
from multiprocessing import Process, Queue

###################################################
#                   Dash Class                    #
#               Time Based Features               #
#                 REQUIRED READING:               #
#   EXPOSURE: Detecting MAlicious Domains Using   #
#    Passive DNS Analysis - Time Based Features   #
###################################################

class dash(list):
    def __init__(self,icq,ocq,started,setcopy):
        # Queues
        self.icq    = icq       # In Queue
        self.ocq    = ocq       # Out Queue
        
        # Default Parameters
        self.started= started   # Time Derpy Dash was started
        self.stime  = started   # Oldest interval available
        self.ctime  = started   # Current time interval
        self.loops  = 0         # number of intervals completed

        # Run algorithm setup
        self.settings = setcopy
        self.setup(setcopy)

        # Algorithm settings, will be deprecated when put into settings file
        self.t_int  = 300       # time intervals, currently set to 1 hr
        self.a_min  = self.t_int*2 # global analysis min, (1 day) abitrary right now, dynamic later
        self.a_max  = self.a_min*2 # max amount of time saved for analysis.  1 week

        # Timing History: {ip:{domain:{time_interval:{'hits':#,'intervals':[time,time,time]}}},}
        self.hist   = {}        # Overall History of queries made
        self.times  = []        # list of all times currently in hist, so we can age them off

        # Event and Change Histories
        self.change = {}        # Changes found for a domain
        self.aevent = {}        # All events generated
        self.cevent = {}        # Events generated this cycle

        # Analysis parameters
        self.a_que  = Queue()   # analysis function's queue, if needed
        self.l_dev  = 0.1       # local deviation used for d(t)-.1
        self.c_max  = 0.4       # cusum max threshhold, S > c_max = Change!

        # start collection and analysis
        self.start()

    
    def setup(self,dsets):
        pass


    class ip_record(list):                      # Retainer for Source IP info
        def __init__(self, name, dom, occurred, ctime):
            self.name       = name
            self.domains    = {dom:self.domain_record(dom,ctime,occurred)}

        class domain_record(list):              # Retainer for domain info within an IP record
            def __init__(self, name, ctime, occurred):
                self.name       = name
                self.int_c_sum  = []            # Cumulative sum history for analysis
                self.intervals  = {ctime:self.time_record(ctime,1,occurred)}

            class time_record(list):            # Retainer for time interval info, within a Domain Record
                def __init__(self,name,hit,occurred):
                    self.name       = name
                    self.hits       = hit       # number of hits
                    self.occurrance = [occurred]# when said hits occurred

                def plusone(self,occurred):     # Adds hit for existing records and record time it occurred
                    self.hits += 1
                    self.occurreance.append(occurred)


    def start(self):
        print '[%s] [Dash] Running' %(time.ctime())
        self.times.append(self.stime)
        while 1:
            try:    # Get from queue, add records
                meta, dom = self.icq.get_nowait()
                self.add_hits(meta,dom[2])
            except: # fail to get from queue, wait 1 second, prevents lockups
                time.sleep(1)
            
            # After each pass check timeframe requirements
            if (time.time()-self.ctime) > self.t_int:   # if new time interval (1hr)
                print '[%s] [Dash] Hourly Change Detection Started' %(time.ctime())
                self.detect_changes()                   # detects changes that occurred this hour
                print '[%s] [Dash] %i IP\'s in change dictionary' %(time.ctime(),len(self.change))
                if self.loops > 24:                     # if at least 24 hrs has been reviewed
                    print '[%s] [Dash] Pattern Detection Started' %(time.ctime())
                    self.analyze()                      # Analyze the changes detected
                self.alert()                            # report any events for current timeframe
                self.time_management()                  # cleans old records

                # if minimum learning threshhold is met, update global analysis
                if self.settings['rainbow'] and self.settings['fusion']:
                    if self.ctime-self.stime >= self.a_min:
                        # real update
                        pass
                    else:
                        if self.settings['fusion']:
                            pass
                            # false update, so other agents can still run, temporary solution for now
                        pass
                    pass


    def time_management(self):
        # Age off old stuff and get ready for the next volly of additions
        self.ctime += self.t_int            # Add interval amount to current time
        self.times.append(self.ctime)       # Add the new time to the times list

        # If we have more than the max allowed time stored
        if self.ctime-self.stime > self.a_max:
            aged = self.times.pop(0)        # remove oldest time interval
            self.stime = self.times[0]      # updated the oldest time

            # cleanup history, remove aged time from source ip's, add new time
            for i in self.hist:
                for j in self.hist[i].domains:
                    if aged in self.hist[i].domains[j].intervals:
                        del self.hist[i].domains[j].intervals[aged]
            self.hist = dict(self.hist)

            # cleanup event records
            self.cevent = {}                # delete current event records
            if aged in self.aevent:    
                del self.aevent[aged]       # delete event history records


    def add_hits(self,meta,dom):
        # get sip and time from metadata
        sip, occurred = meta[0], meta[5]

        # Traverse the dictionary and add what needs to be added
        if sip in self.hist:                        # Check for Source Ip
            lvl = self.hist[sip]
            if dom in lvl.domains:                  # Check for domain
                lvl = lvl.domains[dom]
                if self.ctime in lvl.intervals:     # Check for interval and +1 it
                    lvl.intervals[self.ctime].plusone(occurred)
                else:                               # add new time interval
                    lvl.intervals[self.ctime] = lvl.time_interval(self.ctime,1,occurred)
            else:                                   # add new domain 
                lvl.domains[dom] = lvl.domain_record(dom,self.ctime,occurred)
        else:                                       # add new source ip 
            self.hist[sip] = self.ip_record(sip,dom,occurred,self.ctime)


    def detect_changes(self):
        # This detects traffic pattern changes for the current interval
        # This does not analyze those changes, that is self.analyze()
        for sip in self.hist:                           # We're going to check each ip
            cursip = self.hist[sip]                     # current working ip
            
            for dom in cursip.domains:                  # and each domain on each ip
                curdom = cursip.domains[dom]            # current working domain
                past_hits, future_hits = [],[]          # "past" and "future hits

                # from here, we start cusum algorithm, if intervals[t] fails, assume 0
                for t in self.times[-16:-8]:            # get "past" hits
                    if t in curdom.intervals:           # Check if interval exists
                        past_hits.append(curdom.intervals[t].hits) # get hits if it does
                    else:                               # if it doesn't
                        past_hits.append(0)             # no hits seen during that period

                for t in self.times[-8:]:               # get "future" hits
                    if t in curdom.intervals:           # Check if interval exists
                        future_hits.append(curdom.intervals[t].hits) # get hits if does
                    else:                               # if it doesn't
                        future_hits.append(0)           # no hits seen during that period
                        
                avg_hits = sum(past_hits+future_hits)/16    # avg number of hits for full range

                # calculate the normalized "change value"
                # See EXPOSURE for details on this algoritm
                dt = max(0,abs((float(sum(past_hits))/8)-float(sum(future_hits)/8))-self.l_dev)
                curdom.int_c_sum.append(dt) # add change value to domains change value history
                
                # check threshholds
                if len(curdom.int_c_sum) >= 8:      # ensure we have 8 hours of computations
                    if len(curdom.int_c_sum) > 8:   # if we've got more than 8 (9)
                        curdom.int_c_sum.pop()      # get rid of the oldest

                    S = sum(curdom.int_c_sum)       # calculate the cumulative sum of the 8 hours

                    # if S is > c_max (reporting threshhold), and newest change value is a local max
                    if S > self.c_max and dt == max(curdom.in_c_sum):
                        # change detected! add to change dictionary: {sip:{domain:{time:avg_hits}}}
                        if sip in self.change: 
                            event = self.change[sip]                            # Sip already there?
                            if self.times[-1] in event:
                                event[self.times[-1]]                           # dupe time entries? odd
                                print '[%s] [Dash] Duplicate times in event dictionary' %(time.ctime())
                            else:
                                event[self.times[-1]] = avg_hits                # add time entry
                        else: 
                            self.change[sip] = {dom:{self.times[-1]:avg_hits}}  # add sip if not there
        

    def analyze(self):
        # Here we will do local pattern detect between the recorded changes
        # after an extended time of collection, we will also start passing info to global (short lives)
        # Rainbow Love will handle recombining short live derpy.jack data to detect botnets
        # For now we'll spit out the top 10, bottom 10, and middle 10 avg hits, and the stats for that day
        hits2sip = []
        for sip in self.change:
            cursip = self.change[sip]
            for d in cursip:
                hits = 0
                for t in cursip:
                    hits += cursip[t]
                hits2sip.append([hits,sip,d])
        sorts = sorted(hits2sip)
        tests = sorts[:10]+sorts[(len(hits2sip)/2)-5:(len(hits2sip)/2)+5]+sorts[-10:]
        file = open('/investigations/gmprice/derpy/wip/dash.csv','w')
        file.write('hits,sip,domain\r\n')
        for i in tests:
            file.write(','.join(map(str,i))+'\r\n')

        # then lets go ahead and try our hand at detecting beaconing
        pass


    def alert(self):
        pass

# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class
