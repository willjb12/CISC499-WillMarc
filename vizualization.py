import os
import sqlite3
import matplotlib.pyplot as plt
import numpy as np

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
def tls_version(db_list):
    tls_versions ={}
    total = 0

    for row in db_list:

        version = row['tls_version']
        if version!='NA':
            if version in tls_versions:
                tls_versions[version] +=1
                total+=1
            else:
                tls_versions[version] = 1
                total+=1
      
    print(tls_versions)
    bar_labels = list(tls_versions.keys())
    values = list(tls_versions.values())
    plt.figure(figsize=(10, 6))
    bars = plt.bar(bar_labels, values, color=['blue', 'red'], width = 0.45)  

    # Optional: Add labels, a title, etc.
    plt.xlabel('TLS Versions')
    plt.ylabel('Amount of Websites Using')
    plt.title('TLS Versions')
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2.0, height, str(height)+" / "+'{:.2f}%'.format((height / total) * 100), ha='center', va='bottom')
    # Show the plot
    plt.show()

#tls_version(db_list)
            
#Distribution among csp directives
def csp_directive_distribution(db_list):
    used_directives = {}
    total = 0
    #for each website entry
    for row in db_list:

        if (row['csp_data'] != 'None') and (row['csp_data'] !='NA'):
            total+=1
            #get each directive
            directives = row['csp_data'].split(';')
            for directive in directives:
                    try :
                        directive_name = directive.split()[0]
                        if directive_name in used_directives:
                            used_directives[directive_name] +=1
                        else:
                            used_directives[directive_name] = 1 
                    except Exception as e:
                        None
    
    new_entry={"Total": total}
    updated_dict = {**new_entry,**used_directives}
    sorted_tuples = sorted(updated_dict.items(), key=lambda item: item[1])

    # Convert the sorted tuples back into a dictionary
    sorted_dict = dict(sorted_tuples)

    keys  = list(sorted_dict.keys())
    values = list(sorted_dict.values())
    plt.barh(keys,values)

    for index, value in enumerate(values):
        plt.text(value,index,(str(value)))

    plt.xlabel('Number of policies')
    plt.ylabel('directives')
    plt.title('Distribution of csp directives')

    
    # Displaying the graph
    plt.show()

#csp_directive_distribution(db_list)
    

def common_features_script_src(db_list):
    used_features = {}
    total = 0

    self_count = 0
    unsafeinline_count = 0
    unsafeeval_count = 0
    nonce_count = 0
    http_count = 0 
    https_count = 0 
    data_count = 0
    general_count = 0
    host_wild_count = 0
    host_path_count = 0
    sha_256_count = 0
    none_count = 0
    #for each website entry
    for row in db_list:
        if 'script-src' in row['csp_data']:
            general = False
            host_wild = False
            host_path = False
            sha_256 = False
            none = False
            directives = row['csp_data'].split(';')
            for directive in directives:
                try:
                    if directive.split()[0] == "script-src":
                        total+=1
                        #print(directive+'\n')
                        
                        #self
                        if 'self' in directive:
                            self_count+=1
                        #unsafe-inline
                        if 'unsafe-inline' in directive:
                            unsafeinline_count+=1
                        #unsafe-eval
                        if 'unsafe-eval' in directive:
                            unsafeeval_count+=1
                        #Nonce
                        if 'nonce' in directive:
                            nonce_count+=1
                        
 
                        #https/http/data
                        entries = directive.split(' ')
                        for entry in entries:
                            #https
                            if entry == 'https:':
                                https_count+=1
                            #http
                            if entry == 'http:':
                                http_count+=1
                            #data
                            if entry == 'data:':
                                data_count+=1
                            #general wild
                            if entry == '*':
                                general = True
                                
                            #host w. wild
                            if ('*' in entry) and ('.' in entry):
                                host_wild = True
                            #host w. path
                            if ('*' not in entry) and ('.' in entry):
                                host_path = True
                            #sha256
                            if ('sha256' in entry):
                                sha_256 = True
                            #none
                            if ("'none'" in entry):
                                none = True
                            
                except:
                    None
            if general == True: general_count+=1
            if host_wild == True: host_wild_count+=1
            if host_path == True: host_path_count+=1
            if sha_256 == True: sha_256_count+=1
            if none == True: none_count+=1

    
    
    
    data_dict = {'self':self_count,'unsafe-inline':unsafeinline_count, 'unsafe-eval' : unsafeeval_count, 'Nonce' : nonce_count, 'https:' : https_count, 
                 'http:' : http_count,'data:':data_count, 'General Wildcard' : general_count,  'Host w. Wildcard' : host_wild_count, 'Host w. Path' : host_path_count, 
                 'SHA-256 Hash' : sha_256_count, 'none' : none_count}
    print(data_dict)
    print('TOTAL: '+str(total))
     
    percentage_dict = {key: '{:.2f}%'.format((value / total) * 100)  for key, value in data_dict.items()}

    fig, ax = plt.subplots(figsize=(8,6))
    rows = len(data_dict)
    cols = 2
    ax.set_ylim(-1, rows)
    ax.set_xlim(0, cols + .5)

    # We'll convert the dictionary into a list of items for easier indexing
    items = list(percentage_dict.items())

    # Adding header text
    ax.text(0.5, rows, 'Feature', weight='bold', ha='left', va='center')
    ax.text(2, rows, 'Count', weight='bold', ha='right', va='center')

    # Loop through the dictionary and place text
    for i, (feature, value) in enumerate(items):
        # Feature
        ax.text(x=0.5, y=rows-i-1, s=feature, va='center', ha='left')
        # Value
        ax.text(x=2, y=rows-i-1, s=value, va='center', ha='right', weight='bold')

        # Draw horizontal line above each row
        if i == 3 or i == 6 or i == 9:
            ax.plot(
                [0, cols + .5],
                [rows-i-1.5, rows-i-1.5],
                ls=':',
                lw='.5',
                c='grey'
            )

    # Draw a horizontal line for the header
    ax.plot([0, cols + .5], [rows-.5, rows-.5], lw='.5', c='black')
    ax.axis('off')
    plt.show()

#common_features_script_src(db_list)



#usage of csp, cspro
def usage_of_cspro(db_list):
    ct = 0
    for row in db_list:
        if row['supports_cspro'] == 'True':

            print(row['supports_cspro'])
            print(row['csp_data'])
            ct+=1
    print("count: "+str(ct))

#distribution of whitelisted domains
for row in db_list:
    if row['csp_data'] != 'None':
        #print(row['csp_data'])
        break
#plaintext vs not
yes = 0
no = 0
for row in db_list:

    plaintext = row['sent_in_plaintext']
    if plaintext == 'True':
        yes+=1
    elif plaintext == 'False' and row['sign_in_failed'] == 'False':
        no +=1
#print("Found in plaintext: "+str(yes))
#print("Sign in success, no plaintext: "+str(no))

