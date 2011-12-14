#!/usr/local/bin/python2.6

import sys,os,re
from struct import unpack, pack
from socket import inet_aton, inet_ntoa
sys.path.append('tools/')
from dbhandle import *

###################################################
#                 ALERT TYPES                     #
# Used by the reporting engine to speed up return #
#    Matches will use ret.update(type) to alert   #
# Non Match/Failure to Match will return the type #
###################################################

D_NO_MATCH    = {# No Matching Entries
                'sigs'      :'',
                'priority'  :0,
                'msg'       :'Domain',
                'partial'   :False
                }

IP_NO_MATCH =   {# IP Whitelisted or Not Found
                'sigs'      :'',
                'priority'  :0,
                'msg'       :'IP',
                'class_id'  :0,
                'white'     :True,
                'top'       :True,
                'partial'   :False,
                'hard'      :False,
                'wildcard'  :False
                }

IP_MATCH    =   {# IP Found in the blacklist
                'msg'       :'Blacklisted IP',
                'top'       :False,
                'partial'   :False,
                'hard'      :True,
                'wildcard'  :False
                }

SUS_TLD     =   {# Top Level Domain is suspicious
                'sigs'      :'',
                'priority'  :2,
                'msg'       :'Suspicious Top Level Domain',
                'class_id'  :0,
                'partial'   :False,
                'white'     :True,
                'top'       :True,
                'hard'      :False,
                'wildcard'  :False
                }

PARTIAL     =   {# Found a partial match
                'msg'       :'Partial Blacklisted Domain',
                'priority'  :3,
                'partial'   :True
                }

HARD_MATCH  =   {# Searched domain was found exactly 
                'msg'       :'Blacklisted Domain',
                'partial'   :False
                }

HARD_WILD   =   {# Searched domain had a subdomain, matched a signature, and the signature was wildcarded
                'msg'       :'Blacklisted Domain (Subdomain wildcard)',
                'partial'   :False
                }

HARD_NOWILD =   {# Searched domain had a subdomain, matched a signature, but the signature was not wildcarded
                'msg'       :'Soft Blacklisted Domain (no wildcard)',
                'partial'   :True
                }
				


###################################################
#              Support Functions                  #
#   These take various input and output a list    #
#   List is 1's and 0's and reversed for .pop()   #
#   [1,0,1,0,1,0,1,0,1,0,1,0,1,0,0,0,1,1,1,1,0]   #
###################################################


def pack2bin(ip):       # converts a packed ip (binary data) to a binary list
    fin =  bin(unpack('>I',ip)[0]).lstrip('0b') # convert to binary, strip marker 0b
    fin = ('0'*(32-len(fin)))+fin               # pad with 0's as needed to make it 32 bits long
    return list(fin)[::-1]                      # convert to list, reverse, return 


def dotted2bin(ip):     # converts a dotted decimal ip to binary list
    try:                # errors occur occasionally, check for them
        fin = bin(unpack('>I',inet_aton(ip))[0]).lstrip('0b')   # convert to binary, strip 0b
        fin = ('0'*(32-len(fin)))+fin                           # pad with 0's as needed
        return list(fin)[::-1]                                  # list, reverse, return
    except:             # if error, return None
        return None


def range2list(range):  # Used for converting a range (1.0.0.0-1.0.0.6) into a list of binary lists.
    start,end = range.split('-')                            # identify start/end
    amount = (unpack('>I',inet_aton(end))[0]-unpack('>I',inet_aton(start))[0])  # figure out how many between
    f = [dotted2bin(start)]                                 # convert first, and start list
    start = unpack('>I',inet_aton(start))[0]                # convert start to decimal       
    while amount > 0:                                       # for each inbetween
        amount -= 1                                         # -1 to amount left
        start += 1                                          # +1 to start value
        f.append(dotted2bin(inet_ntoa(pack('>I',start))))   # convert new start value, add to list
    return f                                                # return the full list


def dec2bin(dec):       # converts a decimal ip (1000000234) to reversed binary list
    fin = bin(dec).lstrip('0b')         # convert to binary, strip 0b
    fin = ('0'*(32-len(fin)))+fin       # pad with 0's as needed
    return list(fin)[::-1]              # convert to list, reverse, return				


###############################################
#                Reporting                    #
#     unused, put in for future reference     #
###############################################

def write_cef(hostname,meta,lvl,sig,app,msg):
    if meta[4] == 6:
        proto = 'TCP'
    else: 
        proto = 'UDP'
    cefout = "CEF:0|HERPDERP|MOOPSIE|42.0|"  +\
                sig+"|"                 +\
                hostname+"|"            +\
                str(lvl)+"|"            +\
                "end="+meta[5]+" "      +\
                "src="+meta[0]+" "      +\
                "spt="+str(meta[1])+" " +\
                "dst="+meta[2]+" "      +\
                "dpt="+str(meta[2])+" " +\
                "proto="+proto+" "      +\
                "msg="+app+" "+msg+"\n"
    #ceflog.write(cefout)
	
##############################################
#          Domain and IP Classes             #
##############################################
class domain(list):
    def __init__(self,name,level,white):
        self.name       = name      # domain name
        self.top        = False     # T/F - Top level domain
        self.white      = white     # T/F - White listed?
        self.hard       = False     # Is this a hard entry or a soft entry
        self.sdwc       = False     # T/F - Wildcard for subdomains
        self.level      = level     # domain level (com = 1, google = 2)
        self.class_id   = 0         # Denotes the type of event
        self.priority   = 0         # 1-10 (absolute), -10 to +10 (relative)
        self.subdomains = {}        # subdomains!


    def search(self,doi,fin):
		'''
		Uses iterable of a domain split by '.' - [mail,google,com]
        Search self.subdoamins for last item in the interable (doi[-1]) and calls that subdomain's search function (think recursion)
        Repeat until subdomains does not have doi[-1], or doi[-1] is empty
        we're also passing fin, which is adding all the doi[-1]'s together to get the "signature"
		'''
		
        try:
            return self.subdomains[doi[-1]].search(doi[0:-1],str(doi[-1]+'.'+fin))
        except: 
            # once search fails or doi[-1] doesn't exist, return information on current levels search
            return {'white'     :   self.white,
                    'top'       :   self.top,
                    'sigs'      :   fin,
                    'class_id'  :   self.class_id,
                    'priority'  :   self.priority,
                    'hard'      :   self.hard,
                    'wildcard'  :   self.sdwc
                    }


class bit(list):
    def __init__(self,value,eom):
        self.value      = value     # 0 or 1
        self.eom        = not(eom)  # T/F : End of Mask (on a signature), used for CIDR matching
									# note: using not(eom) was done as a bandaid fix because the database value was switched
        self.class_id   = 0         # Denotes the type of event
        self.priority   = 0         # priority to report to arcsite (-10/10)
        self.subbits    = {}        # The next bits in line.
        self.sigs       = []        # populates with ID's of the signatures it is related to.


    def search(self,ip):
		'''
		Uses iterable of binary ip, low order bit FIRST
        Takes the last item in the interable (doi[-1]), if self.bits has the key, it calls that bit's search function (think recursion)
        Repeats until .subbits does not have doi[-1], or if doi is empty
		'''
		
        try: 
            return self.subbits[ip[-1]].search(ip[0:-1])
        except: 
            return {'white'     : self.eom,
                    'sigs'      : ','.join(self.sigs),
                    'priority'  : self.priority,
                    'class_id'  : self.class_id,
                    }

###############################################
#       List Importation and Updating         #
###############################################

# Testing value, change to testing='' to disable
#testing = ''
testing = 'or (________ = _ and _______ > (CURDATE() - INTERVAL _ DAY))'

def domain_top():       # Retrieves Top Level Domains
    return list(dbsearch('select ________ from __________ where ______ = _'))


def domain_country():   # Retrieves Country Codes (CC) and some Second Level Domains (SLD)
    return list(dbsearch('select ________ from __________ where ______ = _'))


def domain_black():     # Retrieves Blacklisted Domains
    return list(dbsearch('select _______,________,_______ from _______ where((______ = _) and ________ = "_" and (________ = _ or _______ = _ '+testing+'))'))


def domain_white():     # Retrieves Whitelisted Domains
    return list(dbsearch('select _______,________,_______ from _______ where((______ = _) and ________ = "_" and (________ = _ or _______ = _ '+testing+'))'))


def ip_black():         # Retrieves Single, Cidr, and Ranged Blacklisted IP Addresses
    single = dbsearch('select _______,________,_______ from _______ where((______ = _) and ________ = "_" and (________ = _ or _______ = _ '+testing+'))')
    cidr = dbsearch('select _______,________,_______ from _______ where((______ = _) and ________ = "_" and (________ = _ or _______ = _ '+testing+'))')
    ranges = dbsearch('select _______,________,_______ from _______ where((______ = _) and ________ = "_" and (________ = _ or _______ = _ '+testing+'))')
    return {'single':single,'cidr':cidr,'range':ranges}


def ip_white():         # Returns Whitelisted IPs (singles only)
    return dbsearch('select _______,________,_______ from _______ where((______ = _) and ________ = "_" and (________ = _ or _______ = _ '+testing+'))')


def categories():       # Returns Event Classes (i.e. "Known Good" or "Known Bad") and their priority level
    return dbsearch('select ________,_________ from _________;')



###############################################
#              Data Structures                #
###############################################

######################
# Domain and IP Tree #
######################
class tree(list):
    def __init__(self):
        self.domains        = {}        # Domain Tree for domain searches
        self.bits           = {}        # Binary tree for ip searches
        self.cats           = {}        # Category:Priority dictionary
        self.lastupdated    = 0         # Time the tree was last updated, used by update
        self.update()                   # Setup the intial tree's
    
    def update(self):
        # Attempt to update self only if the database has changed #
        dbopen()
        updated = dbsearch('select ____ from ________ order by time desc limit 1')[0][0]
        if updated > self.lastupdated or not self.domains or not self.bits:
            # Set the "changed" value to False
            dbinsert("update _______ set value = '_'")

            # Clear the current blacklist #
            self.domains    = {}
            self.bits       = {}

            # Get fresh categories
            self.cats       = {}
            for cat in categories():
                self.cats[cat[0]] = cat[1]

            # Update domains and ips #
            self.update_domains()
            self.update_bits()

            # Set new updated time
            self.lastupdated = updated
        dbclose()


    def domain_search(self,item):
        # Search on a dotted decimal or decimal IP, a string domain, or an in-addr.arpa resolution
        preformat = item.lower().lstrip('http:').lstrip('//').lstrip('\\\\').lstrip('www.').rstrip('.').lstrip('.')
        
		if re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',item):
            # Dotted decimal IP, do an IP Search instead
            return self.ip_search(item)
        elif re.match('\d{1,10}$',item):
            # Decimal IP, do an IP search instead
            return self.ip_search(int(item))
        elif item.endswith('.in-addr.arpa'): 
            # Reverse DNS Query (ip -> domains), format the ip and do an IP Search instead 
            doi = item.rstrip('.in-addr.arpa').split('.')
            doi = '.'.join(((['0']*(4-len(doi)))+doi)[::-1])
            return self.ip_search(doi)
        else: 
            # Regular domain, Continue on with the Domain Search
            doi = item.split('.')
			
        try: 
            ret = self.domains[doi[-1]].search(doi[0:-1],doi[-1])
            if ret['white'] == False:               # Is "Not whitelisted" (i.e. "In the blacklist")
                if ret['hard']:                     # This is some sort of hard match
                    if item != ret['sigs']:         # identify if domain has a subdomain
                        if ret['wildcard'] == True: # identify as Hard match w/ subdomain wildcard 
                            ret.update(HARD_WILD)
                        else: 
                            ret.update(HARD_NOWILD) # identify as Hard match, w/o subdomain wildcard ("Partial")
                    else:                           # Domain does not have a subdomain
                        ret.update(HARD_MATCH)      # identify as Exact match
                else:
                    ret.update(PARTIAL)             # identify as Partial match
                return ret
            else:                                   # Whitelisted or No match at all, return "Domain"
                ret.update(D_NO_MATCH)              # set No Match 
                return ret
        except:                                     # Unable to resolve TLD to known TLD
            return SUS_TLD                          # Returns suspicious TLD answer


    def ip_search(self,ip):
        '''Search on dotted decimal ip, raw binary ip, or an integer ip.'''
        if type(ip) == str:
		
            if len(ip) == 4:			# This is 4 byte binary ip
                ip = pack2bin(ip)		# convert binary IP to reversed binary list: [0,1,...]
            elif re.match('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',ip):	# this is a dotted decimal
                ip = dotted2bin(ip)		# convert dotted decimal ip to reversed binary list [0,1,...]
        else:
            # This is an integer ip, convert to reverse binary list [0,1,...]
            ip = dec2bin(ip)
			
        try: 
            ret = self.bits[ip[-1]].search(ip[0:-1])# search bit dictionary w/ reverse binary list
            if not ret['white']:                    # If not Whitelisted (i.e. "In the blacklist")
                ret.update(IP_MATCH)                # Set Match Answer
            else:                                   # If Whitelisted
                ret.update(IP_NO_MATCH)             # Set No Match Answer
            return ret                              # Return answer
        except: 
            return IP_NO_MATCH                      # Fail at first bit level: Return No Match answer


    #################
    # Tree Building #
    #################

    def update_domains(self):                       # Domain Tree building
        # Get TLDs and CC first
        tops,countries = domain_top(), domain_country()
		
        while len(countries) > 0:                   # add countries first
            tempdom = domain((countries.pop()[0]).lower(),1,True)
            tempdom.top = True                      # CC's are "Top Level Domains"
            # add generic domains to the country domains (com.co, co.uk, etc)
            for i in tops: 
                tempdom.subdomains[i[0]] = domain(i[0],2,True) 
                tempdom.subdomains[i[0]].top = True # These are also "Top Level Domains"
            self.domains[tempdom.name] = tempdom
			
        while len(tops) > 0:                        # add top level domains last
            tempdom = domain((tops.pop()[0]).lower(),1,True)
            tempdom.top = True
            if tempdom.name in self.domains: 
                pass                                # Check to see if has been added already
            else: 
                self.domains[tempdom.name] = tempdom# add if not
        
        # Need to add "Generic Second Level Domain" support
        pass

        # Black and Whitelist
        d = [domain_white(),domain_black()]
        while d:
            dlist = d.pop()         # remove the last list in d (black first, white second)

            # We're going to use the length of d to determine what that list's ['white'] attribute is
            # Use this so we can use the same code for both lists easily.
            if d: 
				whitelist = False    # if d has something in it, Blacklist entries ['white']=False
            else: 
				whitelist = True     # if not we're adding Whitelist entries, ['white']=True

            # now lets add domains
            while dlist:
                # identify the domain's wildcard status (T/F) and class_id
                wildcard, class_id = dlist[-1][1], dlist[-1][2]
                if wildcard == 'Y': 
                    wildcard = True
                else: 
                    wildcard = False

                # Format the domain into a list split by '.' (e.g. [mail,google,com])
                doms  = dlist.pop()[0].lower().split('.')
                first = doms.pop()  # get the first level domain ('com')

                # Now add/use the TLD entry
                try:
                    # Check if TLD already exists, if it does use it as your current level
                    curtop = self.domains[first]
                except:
                    # if it doesn't exist, we need to add it
                    self.domains[first] = domain(first, 1, True)    # ALWAYS whitelist top lvl domain
                    curtop = self.domains[first]                    # Save to the tree
                    curtop.top = True                               # use as current level

                # Now add the rest of the domain ([mail,google])
                loop = 0    # this will be used for further whitelisting
                while doms:
                    dom = doms.pop()                            # get last entry (google)
                    loop += 1                                   # add 1 to the loop

                    try:
                        # if it is in the tree, use as current level.  If SLD, we need to check something
                        curtop = curtop.subdomains[dom]         # check if it's in the list
                        if (loop == 1 and len(dom) < 3) or whitelist:
                            # if the length of the second level domain is < 3, ensure it's whitelisted
                            # 1-2 character SLD's are reserved, and we can assume are inherently non-malicious by themselves
                            curtop.white = True
                    except:
                        # if it is not in the tree, add it!  If this is an SLD, we need to check something
                        curtop.subdomains[dom] = domain(dom, curtop.level+1, whitelist)
                        curtop = curtop.subdomains[dom]
                        if doms and loop == 1 and (len(dom) < 3 or self.domains.has_key(dom)):
                            curtop.white = True

                # Now that there are no domains left in doms, we are at the top of the signature (mail)
                curtop.hard = True      # This will be our "Hard Match" level
                curtop.sdwc = wildcard  # This is also where we will use the subdomain wildcard feature (T/F)
                
                # Assign a class/priority
                try:
                    if curtop.priority < self.cats[class_id]:   # If stored priority < current one
                        curtop.class_id = class_id              # Use the new class_id and priority
                        curtop.priority = self.cats[class_id]   # This forces usage of highest-priority class 
                except:                                           # If class_id is not in cat dictionary
                    curtop.class_id = class_id                  # use class_id
                    curtop.priority = 5                         # default priority to 5


    def update_bits(self): # Bit Tree building
        # Each blacklist (single,range,cidr) has its own conversion methods
        # We're converting the ip/ip range/cidr in to reverse binary lists (i.e. [0,1,...])
        blacks = ip_black()                     # Get the blacklists
        for ip in blacks['single']:
            try:    pri = self.cats[ip[1]]      # Try to get priority from class_id
            except: pri = 5                     # Otherwise default to 5
            self.add_bits(dotted2bin(ip[0]),32,ip[0],True,pri,ip[1])
			
        for range in blacks['range']:       
            try:    pri = self.cats[range[1]]   # Try to get priority from class_id
            except: pri = 5                     # Otherwise default to 5
            for ip in range2list(range[0]):
                self.add_bits(k,32,ip[0],True,pri,range[1])
				
        for cidr in blacks['cidr']:
            k   = cidr[0].split('/')
            try:    pri = self.cats[cidr[1]]    # Try to get priority from class_id
            except: pri = 5                     # Otherwise default to 5
            self.add_bits(k[0],k[1],cidr[0],True,pri,cidr[1])

        # Now do the same for whitelist.  We only whitelist individual IP Addresses
        for ip in ip_white(): 
            try:    pri = self.cats[ip[1]]      # Try to get priority from class_id
            except: pri = 5                     # Otherwise default to 5
            self.add_bits(dotted2bin(ip[0]),32,ip[0],False,pri,ip[1])


    def add_bits(self,ip,cidr,sig,type,priority,class_id):
        # This will add ip's to the bit tree (self.bits)
        # Please review the bit class at the top before reading this section

        # Get the first bit, similar to our "TLD" section in the black/white portion of update_domains
        newbit = ip.pop()
        try:                                        # check if first bit is already there
            curbit = self.bits[newbit]              # if so, use that as our current level of the tree
        except:
            self.bits[newbit] = bit(newbit,False)   # if not, assign it a new bit
            curbit = self.bits[newbit]              # use that addition as the current level

        # The cidr is what will tell us where the "Top" level of a signature is
        # Since we want to support cidrs, the "Top" level, will be the last bit of the cidr
        cidr -= 1
        while ip:                                   # while there are bits left to add
            # We will add all but the last Network bit the same
            while cidr > 1:
                newbit = ip.pop()                   # get the new bit
                try:                                # check if it's in the tree already
                    curbit = curbit.subbits[newbit] # if it is, use as current level
                except:                             # if not in the tree
                    curbit.subbits[newbit] = bit(newbit,False) # add the new bit
                    curbit = curbit.subbits[newbit] # use the new bit as the current level
                cidr -= 1                           # subtract one from the cidr, and repeat

            # Now that we're on the last network bit, we'll add those and the host bits the same
            newbit = ip.pop()                       # Get the new bit
            try:                                    # check if it is in the tree already
                curbit = curbit.subbits[newbit]     # if it is, use as current level
            except:                                 # if not in the tree
                curbit.subbits[newbit] = bit(newbit,type) # add the new bit, with black/white status
                curbit = curbit.subbits[newbit]     # use the new bit as the current level
                curbit.sigs.append(sig)             # attach the signature to the signature list

        if curbit.priority < priority:      # This forces the highest Priority to be alerted
            curbit.priority = priority      # Incase of an ip falling under two signatures
            curbit.class_id = class_id      # assign it the class id

# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class