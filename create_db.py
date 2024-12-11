import mysql.connector  as myC
connection=myC.connect(
    host='localhost',
    port='3306',
    user='root',
    password='12345678'
)
cursor=connection.cursor()

cursor.execute("SHOW DATABASES;")
records=cursor.fetchall()
for r in records:
    print(r)


cursor.close()
connection.close()
