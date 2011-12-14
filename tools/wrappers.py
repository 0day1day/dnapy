'''

Personal Libraries (c) Gregory Price 2011

'''

### Convert IP addresses from Dotted|Decimal|Hex to Dotted|Decimal|Hex
class ipmagic(list):
    def __init__(self):
        from socket import inet_aton, inet_ntoa
        from struct import unpack, pack
        
    def dot2dec(self, ip):
        # turns dotted decimal into decimal ip
        return unpack('>I',inet_aton(IP))[0]

    def dec2dot(self, dec):
        # turns decimal into dotted decimal
        return inet_ntoa(pack(">I",dec))

    def hex2dec(self, hex):
        # turns a 4byte Hex string into decimal ip
        return struct.unpack('>I',ip)[0]

    def dec2hex(self, dec):
        # turn decimal into Hex
        return struct.pack('>I',dec)

    def hex2dot(self, hex):
        # turns 4 byte hex string into dotted decimal ip
        return dec2dot(hex2dec(hex))
    
    def dot2hex(self, ip):
        # turn dotted decimal to 4 byte hex string
        return dec2hex(dot2dec(ip))




### MySQLdb interface ###
class squirrel(list):
    def __init__(self, h, u, p, d):
        import MySQLdb
        self.conn = None
        self.curs = None
        self.h = h
        self.u = u
        self.p = p
        self.d = d

    def open(self):
        self.conn = MySQLdb.connect(host=self.h,user=self.u,passwd=self.p,db=self.d)
        self.curs = conn.cursor()

    def close():
        self.conn.commit()
        self.conn.close()

    def select(sql):
        self.curs.execute(sql)
        return self.curs.fetchall()

    def insert(sql):
        self.curs.execute(sql)
        self.conn.commit()
        return

    def bulkinsert(sqllist):
        for sql in sqllist:
            self.curs.execute(sql)
        self.conn.commit()
        return



### check if a process is already running, and if so, closes it ###
class checkprocess(list):
    def __init__(self):
        from subprocess import Popen, PIPE

    def check(arg1,arg2):
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
