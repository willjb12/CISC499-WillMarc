import os
import sqlite3
cwd = os.getcwd()
connection = sqlite3.connect(cwd+"/db/test3.db")
cursor = connection.cursor()



#JUST ADDED v
cursor.execute("SELECT * FROM websites")
columns = [description[0] for description in cursor.description]

    # Fetch all rows from the last executed statement
rows = cursor.fetchall()
# Print each row with labeled columns
for row in rows:
    row_with_labels = {columns[i]: row[i] for i in range(len(columns))}
    print(row_with_labels)
connection.close()
print("over")   