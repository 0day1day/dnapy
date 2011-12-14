# generic domain tools, such as TLD/CC detection

import sys
sys.path.append('')
from dbhandle import *

class domain(list):
    def __init__(self,name):
        self.name = name            # domain name
        self.subdomains = {}        # subdomains!

def domain_top():       # Retrieves Top Level Domains
    return list(dbsearch(''))

def domain_country():   # Retrieves Country Codes (CC) and some Second Level Domains (SLD)
    return list(dbsearch(''))

def tld_update():
    dbopen()
    countries   = domain_country()
    tops        = domain_top()
    tld = {}            # dict for formatting so we can return the completed tree
    while countries:    # Add Country Codes first, just like blips
        tempdom = domain((countries.pop()[0].lower()))
        for i in tops:  # Add TLDs as SLDs on CC domains
            tempdom.subdomains[i[0]] = domain(i[0])
        tld[tempdom.name] = tempdom
    del countries       # cleanup
    while tops:         # Now add TLDs
        tempdom = domain((tops.pop()[0].lower()))
        if tempdom.name not in tld:
            tld[tempdom.name] = tempdom
    del tops;           # cleanup
    return tld

def tld_detect(d):
    # formats a domain into: ["second" level, full top level, complete domain]
    # same as blips formatter
    domlist = d.lower().split('.')
    nlvl = domlist.pop()
    if nlvl in TLD:
        curdom = TLD[nlvl]
    else:   # tld not in tld dictionary
        if re.match('\d{1,10}$',d):
            # domain is a decimal ip, return it
            # return [d,d,d]
            return None
        else:
            # return error
            return None
    if nlvl == 'arpa':
        return None
    full_tld = nlvl
    full_domain = nlvl
    while 1:
        if domlist:
            nlvl = domlist.pop()
        else: 
            break
        full_domain = nlvl+'.'+full_domain
        if nlvl in curdom.subdomains:
            curdom = curdom.subdomains[nlvl]
            full_tld = nlvl+'.'+full_tld
        else:
            break
    # return ["second" level domain, full tld, complete domain]
    return [nlvl,full_tld,full_domain]

TLD = tld_update()

# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class
