# used to check to see if the current process is running.
# Use arg1 = python/perl/etc, arg2 = script name.

from subprocess import Popen, PIPE

###################################################
################### Functions! ####################

def checkprocess(arg1,arg2):
    final = []
    command = "ps -ef | grep '%s' | grep '%s' | grep -v grep" %(arg1, arg2)
    temp = Popen(command, shell=True, stdout=PIPE)
    fresh = str(temp.communicate()[0]).split('\n')
    if fresh[0]:
        fresh.pop()
        return len(fresh)-1
    else:
        return 0

# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class
