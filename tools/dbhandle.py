# Simple MySQLdb functions for use by scripts.

import MySQLdb

###################################################
################### Functions! ####################

def dbopen():
    global conn
    global curs
    conn = MySQLdb.connect(host='',user='',passwd='',db='')
    curs = conn.cursor()

def dbclose():
    global conn
    conn.commit()
    conn.close()

def dbsearch(sql):
    global curs
    global conn
    curs.execute(sql)
    return curs.fetchall()

def dbinsert(sql):
    global curs
    global conn
    curs.execute(sql)
    conn.commit()
    return

def dbbulkinsert(sqllist):
    global curs
    global conn
    for sql in sqllist:
        curs.execute(sql)
    conn.commit()
    return


# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class
