import MySQLdb

conn=MySQLdb.connect(host="localhost",user="root",passwd="javajava",db="muyun")
cursor = conn.cursor()
cursor.execute("select * from contacts where id1=%s", 2)
print cursor
member = cursor.fetchall()
print member
rlist=[]
for item in member:
    cursor.execute("select uid, name, realname, language_id from users where uid=%s", item[2] )
    nlist = ('uid', 'username', 'name','language')
    vlist = cursor.fetchall()
    rlist.append(dict(zip((nlist),(vlist[0]))))
print rlist
