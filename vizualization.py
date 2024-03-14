import os
import sqlite3
import matplotlib
import re
import matplotlib.pyplot as plt
from collections import Counter
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


non_domain = ['unsafe-inline', 'strict-dynamic', 'unsafe-eval', 'none', 'self', 'data:', 'blob:', 'http:', 'https:', 'upgrade-insecure-requests', '*', '', 'mediastream:', 'filesystem:', 'wasm-unsafe-eval', 'unsafe-hashes', 'report-sample', 'inline-speculation-rules', 'wss:', "script", 'about', 'vkcalls:', 'ws:']
nonce_hash = ['sha256-', 'sha384-', 'sha512-', 'nonce-']

def make_values_by_row():
    report_pattern1 = r"report-uri\s+[^;]*;"
    report_pattern2 = r"report-uri\s+([^;]+)$"

    full_pattern = r"\b(?:[a-zA-Z0-9-]+-(?:src|ancestors|action|uri))\s+([^;]+)"
    full_regex = re.compile(full_pattern)

    #multiple_pattern = r"(?<=\s)[^;\s']+(?=[;'])"
    #multiple_regex = re.compile(multiple_pattern)

    single_pattern = r"'([^']+)'"
    single_regex = re.compile(single_pattern)

    # This generates values_by_row and ordered_urls
    # values_by_row is a list of lists of each unique value of the entire corresponding policy, minus report-uri destination
    # ordered_urls are the associated urls to each value in the list
    values_by_row = []
    ordered_urls = []
    for row in db_list:
        if row["header_failed"] != True and row['csp_data'] != 'None':
            csp_data = re.sub(report_pattern1, '', row['csp_data'])
            csp_data = re.sub(report_pattern2, '', csp_data)
            matches = full_regex.findall(csp_data)
            
            if matches == []:
                matches = single_regex.findall(csp_data)

            entries = []
            for vals in matches:
                entries = entries + vals.split(' ')

            entries = set(entries)
            entries = list(entries)

            values_by_row.append(entries)
            ordered_urls.append(row['url'])

    return values_by_row


# domains_by_row is a list of lists of just the domains whitelisted in the policies
def make_domains_by_row(values_by_row):

    domains_by_row = values_by_row

    for domains in domains_by_row:
        i = 0
        while i < len(domains):
            found = False
            domains[i] = domains[i].replace("'", "")

            for a in nonce_hash:
                if a in domains[i]:
                    domains.pop(i)

                    i -= 1

                    found = True
                    break

            if not found and domains[i] in non_domain:
                domains.pop(i)
                
                i -= 1

            i += 1

    return domains_by_row

def make_script_src_by_row():
    script_src_pattern = r"script-src\s+([^;]+);"
    script_src_regex = re.compile(script_src_pattern)

    single_pattern = r"script-src\s+([^;]+)"
    single_regex = re.compile(single_pattern)

    script_src_by_row = []
    ordered_urls = []

    for row in db_list:
        if row["header_failed"] != True and row['csp_data'] != 'None':
            match = script_src_regex.search(row["csp_data"])

            if not match:
                match = single_regex.search(row['csp_data'])

            if match:
                script_src = match.group(1)
                script_src = script_src.split()
                script_src_by_row.append(script_src)
                ordered_urls.append(row['url'])
            else:
                continue

    
    return script_src_by_row, ordered_urls

def parse_for_strict_dynamic():
    script_src_by_row, ordered_urls = make_script_src_by_row()

    strict_dynamic_usage = []
    unsafe_inline_usage = []
    nonce_usage = []
    hash_usage = []
    for policy in script_src_by_row:
        found_sd = False
        found_ui = False
        found_n = False
        found_h = False
        for src in policy:
            if "strict-dynamic" in src:
                found_sd = True

            if "unsafe-inline" in src:
                found_ui = True

            if "nonce" in src:
                found_n = True

            if "sha256-" in src or "sha384-" in src or "sha512-" in src:
                found_h = True

            if found_sd:
                strict_dynamic_usage.append(True)
            else:
                strict_dynamic_usage.append(False)

            if found_ui:
                unsafe_inline_usage.append(True)
            else:
                unsafe_inline_usage.append(False)

            if found_n:
                nonce_usage.append(True)
            else:
                nonce_usage.append(False)

            if found_h:
                hash_usage.append(True)
            else:
                hash_usage.append(False)

    script_src_domains = make_domains_by_row(make_values_by_row())

    script_src_length = []
    for domains in script_src_domains:
        script_src_length.append(len(domains))

    return strict_dynamic_usage, unsafe_inline_usage, nonce_usage, hash_usage, script_src_length

def graph_common_allows():
    domains_by_row = make_domains_by_row(make_values_by_row())

    total_domains = []
    for entries in domains_by_row:
        total_domains = total_domains + entries

    delete_substr = ['*.', 'www.', 'https://', 'wss://', "ws://", "ssl.", ":*"]
    for j in range(len(total_domains)):
        for substr in delete_substr:
            total_domains[j] = total_domains[j].replace(substr, "")

    count_domains = Counter(total_domains)
    domain_freq = count_domains.most_common()

    """ with open("domain_frequency.txt", "w") as output:
        for domain, count in domain_freq:
            output.write(f"{domain},{count}\n") """


    allows = []
    num_allow = []
    for domain, count in domain_freq:
        allows.append(domain)
        num_allow.append(count)

    bars = plt.barh(range(len(allows[0:40])), num_allow[0:40], align='center')
    plt.yticks(range(len(allows[0:40])), num_allow[0:40])
    plt.xlabel('Number of Policies with entry')
    plt.ylabel('Entry')
    plt.title('Top 40 Most Common Whitelist Entries')

    for bar, value in zip(bars, allows):
        plt.text(bar.get_width(), bar.get_y() + bar.get_height()/2, value, 
                va='center', ha='left', fontsize=8)
        
    plt.show()

def graph_strict_dynamic():
    strict_dynamic_usage, unsafe_inline_usage, nonce_usage, hash_usage, script_src_length = parse_for_strict_dynamic()

    num_csp = 0
    for row in db_list:
        if row["header_failed"] != True and row['csp_data'] != 'None':
            num_csp += 1

    num_with_script_src = len(strict_dynamic_usage)


    #Policy categories graph
    num_sd_nh = 0
    num_sd_nh_ui = 0
    num_nh_ui = 0
    num_nh = 0
    num_ui = 0

    usage_cat = []

    for i in range(len(strict_dynamic_usage)):
        if strict_dynamic_usage[i] and (nonce_usage[i] or hash_usage[i]) and not unsafe_inline_usage[i]:
            num_sd_nh += 1
            usage_cat.append("sd_nh")
        elif strict_dynamic_usage[i] and (nonce_usage[i] or hash_usage[i]) and unsafe_inline_usage[i]:
            num_sd_nh_ui += 1
            usage_cat.append("sd_nh_ui")
        elif not strict_dynamic_usage[i] and (nonce_usage[i] or hash_usage[i]) and unsafe_inline_usage[i]:
            num_nh_ui += 1
            usage_cat.append("nh_ui")
        elif not strict_dynamic_usage[i] and (nonce_usage[i] or hash_usage[i]) and not unsafe_inline_usage[i]:
            num_nh += 1
            usage_cat.append("nh")
        elif not strict_dynamic_usage[i] and not (nonce_usage[i] or hash_usage[i]) and unsafe_inline_usage[i]:
            num_ui += 1
            usage_cat.append("ui")
        else:
            usage_cat.append("other")


    percentage_cases = [(num_sd_nh/num_with_script_src)*100, (num_sd_nh_ui/num_with_script_src)*100, (num_nh_ui/num_with_script_src)*100, (num_nh/num_with_script_src)*100, (num_ui/num_with_script_src)*100]
    
    for i in range(5):
        percentage_cases[i] = round(percentage_cases[i], 2)

    sorted_percentages = sorted(percentage_cases, reverse=True)
    
    colors = plt.cm.viridis(np.linspace(0, 1, len(percentage_cases)))

    plt.bar(range(5), sorted_percentages, color=colors)

    for i, percentage in enumerate(sorted_percentages):
        plt.text(i, percentage, f'{percentage:.2f}', ha='center', va='bottom')

    legend_descriptions = {0: 'unsafe-inline', 1: 'unsafe-inline and nonce or hash', 2: 'strict-dynamic, unsafe-inline, and nonce or hash', 3: 'nonce or hash', 4: 'strict-dynamic and nonce or hash'}

    legend_handles = [plt.Rectangle((0,0),1,1, color=colors[i], label=legend_descriptions[i]) for i in range(5)]
    plt.legend(handles=legend_handles, loc='upper right', title='Policies Exclusively with')

    plt.xlabel('Policy Category')
    plt.ylabel('Percentage')
    plt.title('Percentage of script-src Policies Using Combinations of Sources')

    #plt.show()

    #length of policies with strict dynamic and without.
    with_sd_counts = [count for value, count in zip(strict_dynamic_usage, script_src_length) if value]
    without_sd_counts = [count for value, count in zip(strict_dynamic_usage, script_src_length) if not value]

    with_sd_counts = sorted(with_sd_counts, reverse=True)
    without_sd_counts = sorted(without_sd_counts, reverse=True)

    plt.figure()
    plt.barh(range(40), with_sd_counts[0:40], color='blue')
    plt.xlabel('Length of Whitelist')
    plt.ylabel('Policy')
    plt.title('Length of Whitelists for Policies With strict-dynamic')
    plt.tight_layout()

    plt.figure()
    plt.barh(range(40), without_sd_counts[0:40], color='red')
    plt.xlabel('Length of Whitelist')
    plt.ylabel('Policy')
    plt.title('Length of Whitelists for Policies Without strict-dynamic')
    plt.tight_layout()
    

    plt.figure()
    plt.barh(range(150), without_sd_counts[0:150], color='red')
    plt.xlabel('Length of Whitelist')
    plt.ylabel('Policy')
    plt.title('Length of Whitelists for Policies Without strict-dynamic')
    plt.tight_layout()
    plt.show()


graph_strict_dynamic()

        


