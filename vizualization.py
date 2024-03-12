import os
import sqlite3
import matplotlib

print(matplotlib.__version__)
cwd = os.getcwd()
connection = sqlite3.connect(cwd+"/db/websiteinfo.db")
cursor = connection.cursor()

db_list = []
cursor.execute("SELECT * FROM websites")
columns = [description[0] for description in cursor.description]

# Fetch all rows from the last executed statement
rows = cursor.fetchall()
# Print each row with labeled columns
for row in rows:
    row_with_labels = {columns[i]: row[i] for i in range(len(columns))}
    db_list.append(row_with_labels)
connection.close()


#tls versions
tls_versions ={}

for row in db_list:

    version = row['tls_version']
    if version!='NA':
        if version in tls_versions:
            tls_versions[version] +=1
        else:
            tls_versions[version] = 1
      
print(tls_versions)
#Distribution among csp directives
        


#usage of csp, cspro
        


#distribution of whitelisted domains
        

#tls version
