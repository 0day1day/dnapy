# Converts Date|Datetime|Timestamp into Date|Datetime|Timestamp

import datetime, time

def date2stamp(datestring):
    # Date to Timestamp
    # accepts: 2011-11-01
    return int(str(time.mktime(map(int, (timestring.split('-') + [0,0,0,0,0,0])))).split('.')[0])


def datetime2stamp(timestring):
    # Datetime to Timestamp
    # accepts: 2011-11-01 12:05:42 as datetime object
    return int(time.mktime(time.strptime(str(datetime.datetime.isoformat(timestring, ' ')).split('.')[0], "%Y-%m-%d %H:%M:%S")))

def stamp2date(stamp):
    # Timestamp to Date
    return datetime.date.fromtimestamp(stamp)

def stamp2datetime(stamp):
    # Timestamp to Datetime
    return datetime.datetime.fromtimestamp(stamp)
    

# vim:tabstop=4:expandtab:shiftwidth=4:smarttab:softtabstop=4:autoindent:smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class
