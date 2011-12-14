#!/usr/local/bin/python2.6
#
# DERPY 1.0
# (c) Gregory Price, 2011
# 
# DERPY is a DNS Analysis tool with various extentions
#   Agent Framework : Example Framework for an agent
#

import sys, time 

###################################################
#               Explanation goes here!            #
###################################################

class agent_name(list):
    def __init__(self,icq,ocq,started,setcopy):
        # Queues
        self.in_queue   = icq       # In Queue
        self.out_queue  = ocq       # Out Queue (sends it to rainbow love for reporting)
        
        # Run Agent Setup
        self.setup(setcopy)     # send copy of derpy's settings for the agent_dir to find settings file

        # Other Default Settings and Structs not changable by the .ini file
        self.domains = {}
        self.events = {}

        # start collection and analysis
        self.start()

    
    # Setup function
    def setup(self,dsets):
        pass

    # Run the collection and analysis portions
    def start(self):
        print '[%s] [Agent Name] Running' %(time.ctime())
        self.times.append(self.stime)
        while 1:

            # We're going to try to get events from the in_queue
            try:    
                # Get from queue
                meta, dom = self.in_queue.get_nowait()   # get_nowait() raises an exception if there is nothing in the queue
                self.collect(meta,dom[2])          # Collect the information
            except: # fail to get from queue, wait 1 second, prevents lockups
                time.sleep(1)
            
            # After each pass, you can set an extended analysis portion if needed
            if 1:
                print '[%s] [Agent Name] Doing Extended Analysis' %(time.ctime())
                self.analyze()

                print '[%s] [Agent Name] Finished, Detected Things, Sending Alerts' %(time.ctime())
                self.alert()                            # report any events for current timeframe

                print '[%s] [Agent Name] Cleaning up stored information' %(time.ctime()))
                self.space_management()                  # cleans old records


    def space_management(self):
        # manage our memory
        self.events = {}  # Clear the events cache
        self.domains = {} # Clears the domain cache

    def collect(self,meta,dom):
        # Take the metadata and domain record, and do stuff with it
        if dom in self.domains:
            self.domains[dom] += 1  # If we've already seen the domain, add a hit
        else:
            self.domains[dom] = [1]   # Else, record the first hit

    def analyze(self):
        # Analyze the hits you collected
        for dom in self.domains:
            if self.domains[dom] > 100000:
                self.events[dom] = 'Domain hit over 100,000 times!'

    def alert(self):
        # read self.alerts, and send reports to rainbow love using self.out_queue
        # Make sure you review rainbow love formatting documentation so you know what to send
        for dom in events:
            self.out_queue.put(dom,events[dom])

# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class
