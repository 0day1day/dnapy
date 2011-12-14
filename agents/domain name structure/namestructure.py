#!/usr/local/bin/python2.6
#
# DERPY 1.0
# (c) Gregory Price, 2011
# 
# DERPY is a DNS Analysis tool with various extentions
#   Hooves  : Domain name structure analysis (# of vowels, # of numerical chars, character frequency analysis)
#

import sys, re, time
from os import popen
sys.path.append('/investigations/gmprice/generic_imports/')
import domaintools


###################################################
#                   Hooves Class                  #
#             Domain Name Based Features          #
###################################################

class hooves(list):
    #def __init__(self,inq=None,onq=None,starttime,setcopy):
    def __init__(self,starttime,setcopy,inq=None,onq=None):
        # Setup Queues
        self.in_queue   =   inq                 # Input Queue
        self.out_queue  =   onq                 # Output Queue
        
        # Default Settings and Objects
        self.t_time     =   starttime           # testing time interval
        self.hist       =   {}                  # analysis history  {domain:score}
        self.events     =   {}                  # events dict for global analysis
        self.curtime    =   starttime           # for hist {domain:{hits:{time:hits}}}
        self.freqs      =   {'char':{},         # freqs for domains w/ numbers or hyphens, defined by settings file
                            'alpha':{},         # freqs for alphabetic only domains, defined by settings file
                            'tld':{}}           # tld freq scoring

        # Read settings and set algorithm parameters
        self.settings = setcopy
        self.setup()

        # start the process
        self.start()

    
    def setup(self):
        try:
            set_file = open(self.settings['agent_dir']+'settings/hooves.ini')
        except:
            print '[%s][Hooves] settings file missing, closing hooves.' %(time.ctime())
            sys.exit()
        raw = set_file.readlines(); set_file.close()
        test, alg, tld, afreq, cfreq = [],[],[],[],[]
        try:
            for line in raw:
                if line.startswith('#') or not line.rstrip(): continue
                j = line.split('#')[0].lower().rstrip()
                if j == 'test':             curtype = test
                elif j == 'alg':            curtype = alg
                elif j == 'tld_scores':     curtype = tld
                elif j == 'alphafreqs':     curtype = afreq
                elif j == 'charfreqs':      curtype = cfreq
                else:                       curtype.append(j)
            for i in test:
                k = i.split('=')
                if k[1]  == 'on':           self.settings[k[0]] = 1
                elif k[1]== 'off':          self.settings[k[0]] = 0
                elif k[0]=='test_interval': self.settings[k[0]] = int(k[1])
                else:                       self.settings[k[0]] = k[1]
            for i in alg:
                k = i.rstrip().split('=')
                if k[0] == 'common_tlds':   self.common_tlds = k[1].lstrip('[').rstrip(']').split(',')
                elif k[0] == 'ucommon_tlds':self.ucommon_tlds= k[1].lstrip('[').rstrip(']').split(',')
                elif k[1] == 'on':          self.settings[k[0]] = 1
                elif k[1] == 'off':         self.settings[k[0]] = 0
                else:                       self.settings[k[0]] = float(k[1])
            for i in tld:
                j = i.split('=')
                s,m = j[1].split(',')
                self.freqs['tld'][j[0]] = {'score':float(s),'multiplier':float(m)}
            for i in afreq:
                j = i.split('=')
                self.freqs['alpha'][j[0]] = float(j[1])
            for i in cfreq:
                j = i.split('=')
                self.freqs['char'][j[0]] =  float(j[1])
            self.settings['min_num'] -= 1
            del test, alg, afreq, cfreq, tld
            # Finally, setup output files if testing is on
            if self.settings['testing']:
                odir = self.settings['test_output_dir']+str(self.t_time)+'/'
                popen('mkdir '+odir)
                self.settings['test_output_dir'] = odir
                if self.settings['vow_scoring']: self.vow_out = open(self.settings['test_output_dir']+'vow_scores.csv','w+')
                if self.settings['num_scoring']: self.num_out = open(self.settings['test_output_dir']+'num_scores.csv','w+')
                if self.settings['tld_scoring']: self.tld_out = open(self.settings['test_output_dir']+'tld_scores.csv','w+')
                if self.settings['freq_scoring']: self.freq_out = open(self.settings['test_output_dir']+'freq_scores.csv','w+')
                rawout = open(self.settings['test_output_dir']+'settings.ini','w+')
                for i in raw: rawout.write(i)
            del raw
        except:
            print '[%s][Hooves] Error in the settings file. Closing hooves.' %(time.ctime())
            sys.exit()
            

    def start(self):
        print '[%s] [Hooves] Running' %(time.ctime())
        # get info from queue, and analyze the domain
        if not self.settings['testing']:
            # if testing is turned off, get info from live data
            while 1:
                try:
                    meta, dom, type = self.in_queue.get_nowait() # Get dns information from queue
                    self.check(meta,dom,type)           # analyze it
                except:                                     # Nothing in the queue 
                    time.sleep(.5)                          # sleep .5 sec
                    #print 'Error: Queue Size = %s' %(k)
            
                # check if the time has been > 15 minutes, if yes, update global_analysis
                if self.settings['rainbow']:
                    if (time.time()-self.curtime) >= self.settings['fusion_interval']:
                        self.curtime += self.settings['fusion_interval']
                        if self.settings['fusion']:
                            print '[%s] [Hooves] Updating Rainbow Love!' %(time.ctime())
                            report = {  'type':'agent', 'agent':'Hooves',
                                        'event':{'hist':self.hist,'new':self.events }}
                            self.out_queue.put(report)      # send update to Rainbow Love
                        self.events = {}

            if self.settings['collection']:
                if (time.time()-self.t_time) > self.settings['collect_int']:
                    print '[%s][Hooves] Printing History to Collection File: %s' %(time.ctime(),self.settings['collect_output_file'])
                    outfile = open(self.settings['collect_output_file'],'w+')
                    for i in self.hist:
                        outfile.write(i+'\r\n')
                    if not self.settings['collect_rep']: 
                        self.settings['collection'] = 0
                    else:
                        self.t_time = time.time()
        else:
            # Read in the test file
            print 'Reading test file: '+self.settings['test_input_file']
            try: 
                infile = open(self.settings['test_input_file'])
            except:
                print 'Unable to open test_input_file, check configuration file: '+self.settings['test_input_file']
                sys.exit()
            raw = infile.readlines(); infile.close()

            # Analyze the domains in the test file
            print 'Analyzing & writing individual feature files'

            for line in raw:
                self.analyze(domaintools.tld_detect(line.rstrip()))

            # Write results to file
            print 'Writing Results Files to: '+self.settings['test_output_dir']
            try:
                outfile = open(self.settings['test_output_dir']+'combined.csv','w+')
            except:
                print 'Unable to open test_output_file, check configuration file: '+self.settings['test_output_file']
                sys.exit()
            for i in self.hist:
                outfile.write(','.join(map(str,[i,self.hist[i]['score']]))+'\r\n')
            outfile.flush(); self.vow_out.flush(); self.num_out.flush(); self.tld_out.flush(); self.freq_out.flush()
            outfile.close(); self.vow_out.close(); self.num_out.close(); self.tld_out.close(); self.freq_out.close()
            popen('chmod 777 -R '+self.settings['test_output_dir'])
            print 'Finished Testing, view '+self.settings['test_output_dir']+' to see results'

    def check(self,meta,dom,type):
        score = self.analyze(dom)
        if score['score'] >= self.settings['report_threshhold']:
            # add to self.events for global analysis later
            if dom[2] in self.events:
                self.events[dom[2]]['hits'] += 1                        # repeat: +1
            else: 
                self.events[dom[2]] = {'score':score['score'],'hits':1} # else add
            # build individual report
            sig     = dom[2]
            host    = dom[2]
            lvl     = int(score['score'])   # Must use int, scores are floored for priority
            agent   = 'Hooves'
            # message differs for queries vs. aliases
            if type == 'Q':     msg = 'suspicious dns query'                    # Query
            elif type == 'A':   msg = 'dns response returned suspicious alias'  # Alias
            # Put it all together and put the event into the out_queue
            if self.settings['rainbow']:
                report = {  'type'  :'event','agent' :agent,
                            'event' :{  'agent' :agent, 'meta':meta, 'sig':sig,
                                        'host'  :host,  'lvl' :lvl,  'msg':msg }}
                self.out_queue.put(report)


    def analyze(self,form):
        # Analyze a domain and return a score
        # Format the domain and check for a history
        if form[2] in self.hist:
            self.hist[form[2]]['hits'] += 1
            return {'score':self.hist[form[2]]['score'], 'repeat':True,}
        else:
            dom         = form[0]
            top         = form[1].split('.')[-1]
            full_tld    = form[1]
            full_domain = form[2]
        
        # set history
        self.hist[full_domain] = {'score':0,'hits':1,'first':0,'last':0}
        
        # Run filters
        if re.search('(mil|gov|edu)',full_tld):     # No Mil/Gov/Edu websites
            return {'score':0,'repeat':False}
        if re.match('(\d{1,3}\.){3}\d{1,3}',dom):   # No IP addresses
            return {'score':0,'repeat':False}
        
        # Frequency character set reconition
        if re.search('\d|-',dom):   dtype = 'char'  # dom has - or #, use char freqs
        else:                       dtype = 'alpha' # dom has alpha chars only, use alpha freqs
        
        # assuming we pass all the checks, now we can score a brand new domain
        
        return self.scoring(dom, top, full_tld, full_domain, dtype)


    def scoring(self, dom, top, full_tld, full_domain, dtype):
        # Passing those checks, we begin collecting information on the domain
        score, freq, vowels, numbers, hyphens = 0, 0, 0, 0, 0
        for c in dom:                               # for each character in the domain
            if c in self.freqs[dtype]:
                freq += self.freqs[dtype][c]        # Add the frequency of the character to overall
            else: 
                return {'score':0,'repeat':False}   # If there is an error, return False

            if dtype == 'char':                     # if there are numbers/hyphens
                if re.match('\d',c):    
                    numbers += 1                    # collect numbers
                if re.match('-',c):
                    hyphens += 1                    # collect hyphens
            
            if re.match('[aeiouy]',c):
                vowels  += 1                        # collect vowels
        # Metrics used for analysis below
        l   = len(dom)                  # length for later computations
        lnh = len(dom)-numbers-hyphens  # length w/o numbers & hyphens
        hits = 0                        # number of "hits" for a feature

        # actual analysis portions, limit to domains longer than 3 characters
        if l > self.settings['min_len']:
            # Vowel Analysis
            if self.settings['vow_scoring']:
                if lnh:
                    vlr = float(vowels)/lnh     # vowel to length ratio
                    if vowels and vlr < self.settings['vow_ratio']:
                        hits += 1               # +1 to hits
                        temp_s = (1-(vlr/self.settings['vow_ratio']))
                        if self.settings['testing']:
                            self.vow_out.write(','.join(map(str,[full_domain,temp_s]))+'\r\n')
                        if self.settings['weighting']:   score += temp_s*self.settings['vow_weight']
                        else:                       score += temp_s
                    elif not vowels:
                        hits += 1               # +1 to hits
                        temp_s = (self.settings['no_vow']*lnh)
                        if self.settings['testing']:
                            self.vow_out.write(','.join(map(str,[full_domain,temp_s]))+'\r\n')
                        if self.settings['weighting']:   score += temp_s*self.settings['vow_weight']
                        else:                       score += temp_s
            
            # Number Analysis
            if self.settings['num_scoring']:
                if numbers > self.settings['min_num'] and float(numbers)/l >= self.settings['num_ratio']:
                    hits += 1                   # +1 to hits
                    temp_s = (((float(numbers)/l)/self.settings['num_ratio']))+(self.settings['min_num_weight']*(numbers-self.settings['min_num'])) 
                    if self.settings['testing']:
                        self.num_out.write(','.join(map(str,[full_domain,temp_s]))+'\r\n')
                    if self.settings['weighting']:   score += temp_s*self.settings['num_weight']
                    else:                       score += temp_s
            
            # chr/alpha freq threshhold checking
            if self.settings['freq_scoring']:
                if float(freq)/l < self.settings['freq_floor']:   # other alerts OR total frequency/length < 2%
                    hits += 1                   # +1 to hits
                    temp_s = 1-((float(freq)/l)/self.settings['freq_floor']) # 1-(ratio/freq_floor)
                    if self.settings['testing']:
                        self.freq_out.write(','.join(map(str,[full_domain,temp_s]))+'\r\n')
                    if self.settings['weighting']:   score += temp_s*self.settings['freq_weight']
                    else:                       score += temp_s
            
            # if not in 3 most common tld's (pushes them higher)
            if self.settings['tld_scoring']:
                if top in self.freqs['tld']:
                    s,m = self.freqs['tld'][top]['score'], self.freqs['tld'][top]['multiplier']
                    if hits: temp_s = s*(m*hits)
                    else:    temp_s = s
                    if self.settings['testing']: self.tld_out.write(','.join(map(str,[full_domain,temp_s]))+'\r\n')
                    if self.settings['weighting']:   score += temp_s*self.settings['freq_weight']
                    else:                       score += temp_s
            
            # if domain contains 'cdn', -cdn_value to the interesting scale
            if self.settings['cdn_filter']:
                if re.search('cdn',dom):
                    score -= self.settings['cdn_value']
            
            # if domain contains 'dns', -dns_value to the interesting scale
            if self.settings['dns_filter']:
                if re.search('dns',full_domain):
                    score -= self.settings['dns_value']
            
            # if uri starts with ns or dns (nameservers) interest -ns_value (doubling dns remove)
            if self.settings['ns_filter']:
                if re.match('dns|ns\d{1,2}',full_domain):
                    score -= self.settings['ns_value']

        # all said and done, set domain's analysis history and return the score
        if score < 0: score = 0
        self.hist[full_domain] = {'score':score, 'hits':1, 'first':0, 'last':0}
        return {'score':score,'repeat':False}


if __name__ == '__main__':
    print 'Running test.'
    sets = {'fusion':0,'blips':0,'hooves':1,'rainbow':0,'jack':0,'dash':0,'agent_dir':'/investigations/gmprice/derpy/wip/agents/','testing':1}
    analyzers = hooves(time.time(), sets)
    pass

# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class
