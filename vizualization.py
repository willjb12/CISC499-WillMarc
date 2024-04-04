import os
import sqlite3
import matplotlib
import re
import matplotlib.pyplot as plt
from collections import Counter
import numpy as np
import pandas as pd
import math

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
    
def xxss_check(dict_row):

    if(dict_row['supports_xxss'] == 'False'):
        return 0, "no xxss support"
    elif(('1' in dict_row['xxss_data']) and ('block' in dict_row['xxss_data'])):
        return 15, "xxss 1;mode=block"
        #best
    elif(('1' in dict_row['xxss_data']) and ('block' not in dict_row['xxss_data'])):
        return 12, "xxss 1"
        #better
    elif(row['xxss_data'] == '0' or dict_row['xxss_data'] == 'None' or dict_row['xxss_data'] == '' or dict_row['xxss_data'] == 'NA'):
        return 0, "no xxss filter"
        #bad
    else:
        return 0, "unknown xxss"
    
# for row in db_list: 
#     print("XXSS: "+row['supports_xxss']+', '+row['xxss_data']+', Number: '+str(xxss_check(row))+'\n')


def xfo_check(dict_row):
    

    if dict_row['supports_xframe'] == 'False':
        return 0, "no xfo support"
    elif dict_row['xfo_data'].upper() == 'DENY':
        return 15, "xfo deny"
    elif dict_row['xfo_data'].upper() == 'SAMEORIGIN':
        return 15, "xfo sameorigin"
    elif dict_row['xfo_data'].upper() == 'ALLOWALL' or 'ALLOW-FROM' in dict_row['xfo_data'].upper():
        return 0, "xfo allowall/allow-from"
    else:
        return 0, "unknown xfo"

# for row in db_list: 
#     print("XFO: "+row['supports_xframe']+', '+row['xfo_data']+', Number: '+str(xfo_check(row))+'\n')
    
def hsts_check(dict_row):


    if dict_row['supports_hsts'] == 'False':
        return 0, "no hsts support"
    elif 'max-age=0' in dict_row['hsts_data']:
        return 0, "hsts max age 0"
    elif 'max-age' in dict_row['hsts_data']:
        return 20, "hsts good"
    else:
        return 0, "unknown hsts"


# for row in db_list: 
#     print("HSTS: "+row['supports_hsts']+', '+row['hsts_data']+', Number: '+str(hsts_check(row))+'\n')

def referrer_check(dict_row):
    options = dict_row['referrer_data'].split(',')

    if dict_row['supports_referrer_policy'] == 'False':
        return 0, "no ref policy support"
    
    elif 'unsafe-url' in options:
        
        return 0, "ref_pol unsafe-url"
    elif 'no-referrer-when-downgrade' in options:
        
        return 0, "ref_pol no-referrer-when-downgrade"
    elif 'origin' in options:
        
        return 5, "ref_pol origin"
    elif 'origin-when-cross-origin' in options:
        
        return 5, "ref_pol origin-when-cross-origin"
    elif 'strict-origin' in options:
        
        return 5, 'ref_pol strict-origin'
    elif 'strict-origin-when-cross-origin' in options:
        
        return 5, "ref_pol strict-origin-when-cross-origin"
    elif 'no-referrer'in options:
        
        return 10, "ref_pol no-referrer"
    elif 'same-origin' in options:

        return 10, "ref_pol same-origin"
    else:
        return 0, "unknown ref_pol"

# for row in db_list: 
#     print("ref: "+row['supports_referrer_policy']+', '+row['referrer_data']+', Number: '+str(referrer_check(row))+'\n')
    

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


non_domain = ['android-webview-video-poster:', 'unsafe-inline', 'strict-dynamic', 'unsafe-eval', 'none', 'self', 'data:', 'blob:', 'http:', 'https:', 'upgrade-insecure-requests', '*', '', 'mediastream:', 'filesystem:', 'wasm-unsafe-eval', 'unsafe-hashes', 'report-sample', 'inline-speculation-rules', 'wss:', "script", 'about', 'vkcalls:', 'ws:']
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

    return (values_by_row, ordered_urls)


# domains_by_row is a list of lists of just the domains whitelisted in the policies
def make_domains_by_row(values_by_row):

    domains_by_row = values_by_row[0]
    ordered_urls = values_by_row[1]

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

    return domains_by_row, ordered_urls

def get_full_csp():
    report_pattern1 = r"report-uri\s+[^;]*;"
    report_pattern2 = r"report-uri\s+([^;]+)$"

    values_by_row = []
    ordered_urls = []
    for row in db_list:
        if row["header_failed"] != True and row['csp_data'] != 'None':
            csp_data = re.sub(report_pattern1, '', row['csp_data'])
            csp_data = re.sub(report_pattern2, '', csp_data)

            values_by_row.append(csp_data)
            ordered_urls.append(row['url'])
        else:
            values_by_row.append(None)
            ordered_urls.append(row['url'])

    return values_by_row, ordered_urls

def get_vals_by_row_all():
    report_pattern1 = r"report-uri\s+[^;]*;"
    report_pattern2 = r"report-uri\s+([^;]+)$"

    full_pattern = r"\b(?:[a-zA-Z0-9-]+-(?:src|ancestors|action|uri))\s+([^;]+)"
    full_regex = re.compile(full_pattern)

    single_pattern = r"'([^']+)'"
    single_regex = re.compile(single_pattern)

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

            

            values_by_row.append(entries)
            ordered_urls.append(row['url'])
        else:
            values_by_row.append(None)
            ordered_urls.append(row['url'])

    return (values_by_row, ordered_urls)

def make_script_src_by_row():
    script_src_pattern = r"script-src\s+([^;]+);"
    script_src_regex = re.compile(script_src_pattern)

    single_pattern = r"script-src\s+([^;]+)"
    single_regex = re.compile(single_pattern)

    script_src_by_row = []
    ordered_urls = []

    for row in db_list:
        if row["header_failed"] != 'True' and row['csp_data'] != 'None':
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

    script_src_domains, _ = make_domains_by_row(make_values_by_row())

    script_src_length = []
    for domains in script_src_domains:
        script_src_length.append(len(domains))

    return strict_dynamic_usage, unsafe_inline_usage, nonce_usage, hash_usage, script_src_length, (script_src_by_row, ordered_urls)

def graph_common_allows():
    domains_by_row, _ = make_domains_by_row(make_values_by_row())

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

    bars = plt.barh(range(len(allows[0:50])), num_allow[0:50], align='center')
    plt.yticks(range(len(allows[0:50])), num_allow[0:50])
    plt.xlabel('Number of Policies with entry')
    plt.ylabel('Entry')
    plt.title('Top 50 Most Common Whitelist Entries')

    for bar, value in zip(bars, allows):
        plt.text(bar.get_width(), bar.get_y() + bar.get_height()/2, value, 
                va='center', ha='left', fontsize=8)
        
    plt.show()

#graph_common_allows()

def graph_strict_dynamic():
    strict_dynamic_usage, unsafe_inline_usage, nonce_usage, hash_usage, script_src_length, _ = parse_for_strict_dynamic()

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


    percentage_cases = [(num_ui/num_with_script_src)*100, (num_sd_nh/num_with_script_src)*100, (num_sd_nh_ui/num_with_script_src)*100, (num_nh_ui/num_with_script_src)*100, (num_nh/num_with_script_src)*100]

    print(percentage_cases)
    
    for i in range(5):
        percentage_cases[i] = round(percentage_cases[i], 2)

    #sorted_percentages = sorted(percentage_cases, reverse=True)
    
    colors = plt.cm.viridis(np.linspace(0, 1, len(percentage_cases)))

    plt.bar(range(5), percentage_cases, color=colors)

    for i, percentage in enumerate(percentage_cases):
        plt.text(i, percentage, f'{percentage:.2f}', ha='center', va='bottom')

    legend_descriptions = {0: 'unsafe-inline', 1: 'strict-dynamic and nonce or hash', 2: 'strict-dynamic, unsafe-inline, and nonce or hash', 3: 'unsafe-inline and nonce or hash', 4: 'nonce or hash'}

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
    print(len(with_sd_counts))
    print(len(without_sd_counts))

    plt.figure()
    plt.barh(range(60), with_sd_counts[0:60], color='blue')
    plt.xlabel('Length of Whitelist')
    plt.ylabel('Policy')
    plt.title('Length of Whitelists for Policies With strict-dynamic')
    plt.tight_layout()

    plt.figure()
    plt.barh(range(327), without_sd_counts[0:327], color='red')
    plt.xlabel('Length of Whitelist')
    plt.ylabel('Policy')
    plt.title('Length of Whitelists for Policies Without strict-dynamic')
    plt.tight_layout()
    

    # plt.figure()
    # plt.barh(range(150), without_sd_counts[0:150], color='red')
    # plt.xlabel('Length of Whitelist')
    # plt.ylabel('Policy')
    # plt.title('Length of Whitelists for Policies Without strict-dynamic')
    # plt.tight_layout()
    plt.show()

#graph_strict_dynamic()

def graph_cspisdead():
    pass

# number of domains in each policy
def graph_domain_length():
    domains_by_row, ordered_urls = make_domains_by_row(make_values_by_row())
    lengths_by_row = []
    for i in range(len(domains_by_row)):
        lengths_by_row.append(len(domains_by_row[i]))

    pairs = sorted(zip(lengths_by_row, ordered_urls), reverse=True)

    sorted_lengths, sorted_urls = zip(*pairs)
    for i in range(10):
        print(sorted_urls[i], ": ", sorted_lengths[i])

def encrypted_vs_plaintext():
    num_plaintext = 0
    num_encrypted = 0
    num_success = 0
    num_total = 0
    for row in db_list:
        num_total += 1
        if row['sign_in_failed'] == "False":
            num_success += 1
            if row['sent_in_plaintext'] == "True":
                num_plaintext += 1
            else:
                print(row['url'], ": ", row["post_pass"])
                num_encrypted += 1
    
    print("plaintext: ", num_plaintext)
    print("encrypted: ", num_encrypted)
    print("success: ", num_success)
    print("total: ", num_total)

def policy_counts_total():
    total = 0
    with_sd = 0
    with_n = 0
    with_h = 0
    with_ui = 0
    missing_object = 0
    wildcard = 0
    any = 0
    for row in db_list:
        if row['header_failed'] != "True" and row['csp_data'] != "None" and ("script-src" in row['csp_data'] or "default-src" in row['csp_data']):
            total += 1
            found = False
            if row['usage_strict_dynamic'] == "True":
                with_sd += 1
            if row['usage_unsafe_inline'] == "True" and row['num_nonce'] == '0' and row['usage_strict_dynamic'] != "True":
                with_ui += 1
                found = True
            if row['num_hash'] != '0' and row['num_hash'] != "NA":
                with_h += 1
            if row['num_nonce'] != '0' and row['num_nonce'] != "NA":
                with_n += 1
            if row['missing_object_src'] == 'True':
                missing_object += 1
                found = True
            if row["use_of_wildcards"] == 'True':
                wildcard += 1
                found = True
            if found == True:
                any += 1
            

    print("total with script content restriction: ", total)
    print("has strict dynamic: ", with_sd)
    print("has unsafe-inline: ", with_ui)
    print("has nonce: ", with_n)
    print("has hash: ", with_h)
    print("missing object-src: ", missing_object)
    print("has wildcard: ", wildcard)
    print("Percentage trivially bypassable: ", (any/total)*100)

    fig, ax = plt.subplots(figsize=(8,6))
    rows = 7
    cols = 5
    ax.set_ylim(-1, rows)
    ax.set_xlim(0, cols + 2)

    items = [('controls script/\nXXS-protection\npolicies', total, "", "", ""), ('strict-dynamic', with_sd, str(round(with_sd/total, 2)*100)+"%", "0%", "1.0%"), ('nonce', with_n, str(round(with_n/total, 2)*100)+"%", "2.0%", "5.0%"), ('hash', with_h, str(round(with_h/total, 2)*100)+"%", "1.0%", "1.0%"), ('unsafe-inline', with_ui, str(round(with_ui/total, 2)*100)+"%", "87.63%", ""), ('missing object source',missing_object, str(round(missing_object/total, 2)*100)+"%", "9.4%", ""), ('wildcard in policy', wildcard, str(round(wildcard/total, 2)*100)+"%", "21.48%", "")]

    # Adding header text
    ax.text(0.5, rows, 'Feature', weight='bold', ha='left', va='center')
    ax.text(2.5, rows, 'Count', weight='bold', ha='center', va='center')
    ax.text(3.5, rows, 'Percent\n2024', weight='bold', ha='center', va='center')
    ax.text(4.5, rows, 'Percent\n2016\n(Comparison)', weight='bold', ha='center', va='center')
    ax.text(5.75, rows, 'Percent\n2018\n(Comparison)', weight='bold', ha='center', va='center')

    # Loop through the dictionary and place text
    for i, (feature, value, per, six, eight) in enumerate(items):
        # Feature
        ax.text(x=0.5, y=rows-i-1, s=feature, va='center', ha='left')
        # count
        ax.text(x=2.5, y=rows-i-1, s=value, va='center', ha='center', weight='bold')
        # percent
        ax.text(x=3.5, y=rows-i-1, s=per, va='center', ha='center', weight='bold')
        # comaparison 2016
        ax.text(x=4.5, y=rows-i-1, s=six,va="center", ha='center', weight='bold')
        # comparison 2018
        ax.text(x=5.75, y=rows-i-1, s=eight, va='center', ha='center', weight='bold')

        # Draw horizontal line above each row
        if i == 0 or i == 6 or i == 9:
            ax.plot(
                [0, cols + 2],
                [rows-i-1.5, rows-i-1.5],
                ls=':',
                lw='.5',
                c='grey'
            )

    # Draw a horizontal line for the header
    ax.plot([0, cols + 1.5], [rows-.5, rows-.5], lw='.5', c='black')
    ax.axis('off')
    plt.show()


#policy_counts_total()

def script_src_length_boxplot():
    _, _, _, _, script_src_length, _ = parse_for_strict_dynamic()

    plt.figure(figsize=(8, 6))
    plt.boxplot(script_src_length)
    plt.ylabel('script-src policy length')
    plt.grid(True)
    plt.show()




def framing_header_vs_csp_comparison():
    xfo = []
    frame_anc = []
    total = 0

    for row in db_list:
        if row['header_failed'] == "False":
            total += 1
            if row['frame_ancestors_data'] != "None" and row['frame_ancestors_data'] != "NA":
                frame_anc.append(True)
            else:
                frame_anc.append(False)

            if row['supports_xframe'] == "True":
                xfo.append(True)
            else:
                xfo.append(False)


    num_xfo = 0
    num_frame_anc = 0
    num_both = 0
    for i in range(len(xfo)):
        if xfo[i] == True:
            num_xfo += 1
        if frame_anc[i] == True:
            num_frame_anc += 1
        if xfo[i] == True and frame_anc[i] == True:
            num_both += 1

    numbers = [num_xfo, num_frame_anc, num_both]
    labels = ['X-Frame-Options', 'CSP frame-ancestors', 'Both']

    plt.figure(figsize=(8, 6))
    bars = plt.bar(labels, numbers, color='skyblue')
    plt.title("Usage of Framing Controls 2024")
    plt.ylabel('# of Sites')

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, height, f'{int(height)}', ha='center', va='bottom')

    plt.grid(False)
    plt.show()

framing_header_vs_csp_comparison()
    
def comparison_graphs():
    numbers = [3253, 409, 270]
    labels = ['X-Frame-Options', 'CSP frame-ancestors', 'Both']

    plt.figure(figsize=(8, 6))
    bars = plt.bar(labels, numbers, color='skyblue')
    plt.title("Framing Controls 2018")
    plt.ylabel('# of Sites')

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, height, f'{int(height)}', ha='center', va='bottom')

    plt.grid(False)


    numbers = [90, 350, 260, 65, 450]
    labels = ['block-all-mixed-content', 'upgrade-insecure-requests', 'STS', 'Whitelist https: scheme', 'TLS enforcement']

    plt.figure(figsize=(8, 6))
    bars = plt.bar(labels, numbers, color='skyblue')
    plt.title("TLS Enforcement Strategies 2018")
    plt.ylabel('# of Sites')

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, height, f'{int(height)}', ha='center', va='bottom')

    plt.grid(False)
    plt.show()

#comparison_graphs()
    

    
def referrer_header_vs_csp_comparison():
    header = []
    csp = []
    total = 0

    for row in db_list:
        if row['header_failed'] == "False":
            total += 1
            if row['referrer_data'] != "None" and row['referrer_data'] != "NA":
                header.append(True)
            else:
                header.append(False)

            if "referrer" in row['csp_data']:
                csp.append(True)
            else:
                csp.append(False)


    num_csp = 0
    num_header = 0
    num_both = 0
    for i in range(len(csp)):
        if csp[i] == True:
            num_csp += 1
        if header[i] == True:
            num_header += 1
        if csp[i] == True and header[i] == True:
            num_both += 1

    numbers = [num_header, num_csp, num_both]
    labels = ['referrer-policy header', 'referrer CSP', 'Both']

    plt.figure(figsize=(8, 6))
    bars = plt.bar(labels, numbers, color='skyblue')
    plt.title("Usage of referrer ")
    plt.ylabel('# of Sites')

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, height, f'{int(height)}', ha='center', va='bottom')

    plt.grid(False)
    plt.show()

#referrer_header_vs_csp_comparison()


def tls_enforcement_strategies():
    block_all_mixed_content = []
    upgrade_insecure_requests = []
    hsts = []
    whitelist_https = []
    any = []
    total = 0

    for row in db_list:
        if row['header_failed'] != "True":
            total += 1
            found = False
            if "block-all-mixed-content" in row['csp_data']:
                block_all_mixed_content.append(True)
                found = True
            else:
                block_all_mixed_content.append(False)
            if 'upgrade-insecure-requests' in row['csp_data']:
                upgrade_insecure_requests.append(True)
                found = True
            else:
                upgrade_insecure_requests.append(False)
            if 'max-age' in row["hsts_data"]:
                hsts.append(True)
                found = True
            else:
                hsts.append(False)
            if "https: " in row['csp_data']:
                whitelist_https.append(True)
                found = True
            else:
                whitelist_https.append(False)
            if found:
                any.append(True)
            else:
                any.append(False)
        
    num_block_all = sum(block_all_mixed_content)
    num_upgrade = sum(upgrade_insecure_requests)
    num_hsts = sum(hsts)
    num_whitelist = sum(whitelist_https)
    num_any = sum(any)

    block_all_and_upgrade = 0
    for i in range(len(hsts)):
        if block_all_mixed_content[i] == True and upgrade_insecure_requests[i] == True:
            block_all_and_upgrade += 1

    print("Percentage of sites with any tls enforcement: ", (num_any/total)*100)
    print("Number of sites with block-all-mixed-content and upgrade-insecure-requests directives:", block_all_and_upgrade)

    numbers = [num_block_all, num_upgrade, num_hsts, num_whitelist, num_any]
    labels = ['block-all-mixed-content', 'upgrade-insecure-requests', 'STS', 'Whitelist https: scheme', 'TLS enforcement']

    plt.figure(figsize=(8, 6))
    bars = plt.bar(labels, numbers, color='skyblue')
    plt.title("TLS Enforcement Strategies")
    plt.ylabel('# of Sites')

    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, height, f'{int(height)}', ha='center', va='bottom')

    plt.grid(False)
    plt.show()

#tls_enforcement_strategies()


def csp_score():
    score = []
    length_pol = []
    strength_csp = []
    strength_framing = []
    url = []
    descs = []
    
    for row in db_list:
        url.append(row['url'])
        
        
        script_src = None
        default_src = None
        

        pos = len(score)

        descs.append("")
        if row['header_failed'] != 'True' and row['csp_data'] != 'None' and row['csp_data'] != 'NA':
            strong_csp = True
            strong_framing = True
            length_pol.append(int(row['total_policy_length']) + 1)
            score.append(60)
            descs[pos] = descs[pos]+ " has csp,"
            script_src_pattern = r"script-src\s+([^;]+);"
            script_src_regex = re.compile(script_src_pattern)
            single_pattern = r"script-src\s+([^;]+)"
            single_regex = re.compile(single_pattern)

            csp_data = row['csp_data']

            match = script_src_regex.search(csp_data)

            if not match:
                match = single_regex.search(csp_data)

            if match:
                script_src = match.group(1)
                script_src = script_src.replace("'", "")
                script_src = script_src.split()
                

            if not match:
                default_src_pattern = r"default-src\s+([^;]+);"
                default_src_regex = re.compile(default_src_pattern)
                def_single_pattern = r"default-src\s+([^;]+)"
                def_single_regex = re.compile(def_single_pattern) 

                match = default_src_regex.search(csp_data)

                if not match:
                    match = def_single_regex.search(csp_data)

                if match:
                    default_src = match.group(1)
                    default_src = default_src.replace("'", "")


            if row['usage_unsafe_inline'] == 'True' and row['num_hash_script_src'] == '0' and row['num_nonce_script_src'] == '0':
                strong_csp = False
                score[pos] -= 20
                descs[pos] = descs[pos]+ " has weak csp,"
            else:
                if script_src == None and default_src != None:
                    if "unsafe-inline" in default_src:
                        strong_csp = False
                        score[pos] -= 20
                        descs[pos] = descs[pos]+ " has unsafe-inline in default_src,"
            if row['use_of_wildcards'] == 'True':
                strong_csp == False
                score[pos] -= 20
                descs[pos] = descs[pos]+ " has wildcards,"
            elif default_src != None:
                if "https:" in default_src or "http:" in default_src:
                    strong_csp =False
                    score[pos] -= 20
                    descs[pos] = descs[pos] + " has scheme,"
            elif script_src != None:
                if "https:" in script_src or "http:" in script_src and row['usage_strict_dynamic'] == 'False':
                    strong_csp =False
                    score[pos] -= 20
                    descs[pos] = descs[pos] + " has scheme,"
            if row['missing_object_src'] == 'True':
                strong_csp = False
                score[pos] -= 20
                descs[pos] = descs[pos]+ " missing object-src,"

            bad_ancestors = ["http:", "https:", "blob:", "data:", "filesystem:", "mediastream:", "wss:", "ws:", "*", "'*'"]

            score[pos] += 15
            for bad in bad_ancestors:
                if bad == row['frame_ancestors_data'].split():
                    score[pos] -= 15
                    descs[pos] = descs[pos]+ " bad ancestors,"
                    break

            strength_csp.append(strong_csp)
            strength_framing.append(strong_framing)

            if 'upgrade-insecure-requests' in row['csp_data'] or 'block-all-mixed-conent' in row['csp_data']:
                score[pos] += 10
                descs[pos] = descs[pos]+ "supports upgrade,"
        else:
            score.append(0)
            strength_csp.append(False)
            strength_framing.append(False)
            length_pol.append(None)

        score[pos]+=referrer_check(row)[0]
        descs[pos] = descs[pos]+ " "+referrer_check(row)[1]+","
        score[pos]+=hsts_check(row)[0]
        descs[pos] = descs[pos]+ " "+hsts_check(row)[1]+","
        if strong_csp == False:
            score[pos]+=xxss_check(row)[0]
            descs[pos] = descs[pos]+ " "+xxss_check(row)[1]+","
        if strong_framing == False:
            score[pos]+=xfo_check(row)[0]
            descs[pos] = descs[pos]+ " "+xfo_check(row)[1]+","

    return score, url, length_pol, strength_csp, strength_framing, descs

def grade(g):
    if (g>=85):
        return "A"
    elif (70<=g<85):
        return "B"
    elif (60<=g<70):
        return "C"
    elif (50<=g<60):
        return "D"
    elif (g<50):
        return "F"
    

def grading_function():
    ret = csp_score()
    score = ret[0]
    url = ret[1]
    length_pol = ret[2]
    strength_csp = ret[3]
    strengt_framing = ret[4]
    descs = ret[5]
    grades = []
    ret_dict = {}
    for i, thing in enumerate(score,0):
        percent = round((thing/115)*100,2)
        grade_score = grade(percent)

        grades.append(grade_score)
        ret_dict[url[i]+ " "+grade_score] = percent

    return ret_dict, url, grades, length_pol, descs

#grading_function()


def grade_distribution():
    grades = grading_function()[2]
    grade_counts = {grade: grades.count(grade) for grade in "ABCDF"}

    # Data for plotting
    grades_ordered = ["A", "B", "C", "D", "F"]
    counts = [grade_counts.get(grade, 0) for grade in grades_ordered]

    # Grade ranges for annotation
    grade_ranges = {
        "A": "85-100",
        "B": "70-84",
        "C": "60-69",
        "D": "50-59",
        "F": "<50"
    }

    # Create histogram
    plt.figure(figsize=(10, 6))
    bars = plt.bar(grades_ordered, counts, color='skyblue')

    plt.xlabel('Grades')
    plt.ylabel('Frequency')
    plt.title('Frequency of Letter Grades')
    plt.xticks(grades_ordered)

    # Determine the range for y-ticks
    max_count = max(counts)
    y_tick_max = (max_count // 50 + 1) * 50  # Round up to the nearest 50
    y_ticks = np.arange(0, y_tick_max, 50)  # Generate y-ticks at intervals of 50

    plt.yticks(y_ticks)

    # Annotate each bar with the grade range
    for bar, grade in zip(bars, grades_ordered):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width() / 2., height,
                f'{grade_ranges[grade]}', ha='center', va='bottom')

    plt.show()

#grade_distribution()
# for row in db_list:
#     if 'upgrade-insecure-requests' in row['csp_data']:
#         print(row['url']+" "+row['csp_data']+'\n')

def graph_grade_by_whitelist():
    grade = grading_function()
    
    grade_list = grade[2]
    grades = ['A', 'B', 'C', 'D', 'F']

    lengths = []
    for row in get_vals_by_row_all()[0]:
        if row == None:
            lengths.append(None)
        else:
            lengths.append(len(row))


    i = 0
    while i < len(grade_list):
        if lengths[i] == None:
            lengths.pop(i)
            grade_list.pop(i)
            continue
        i += 1

    policy_lengths = [[], [], [], [], []]
    for i in range(len(grade_list)):
        if grade_list[i] == "A":
            policy_lengths[0].append(lengths[i])
        elif grade_list[i] == "B":
            policy_lengths[1].append(lengths[i])
        elif grade_list[i] == "C":
            policy_lengths[2].append(lengths[i])
        elif grade_list[i] == "D":
            policy_lengths[3].append(lengths[i])
        elif grade_list[i] == "F":
            policy_lengths[4].append(lengths[i])
    
    fig, axs = plt.subplots(len(grades), figsize=(8, 10), sharex=True)

    for i, (grade, lengths) in enumerate(zip(grades, policy_lengths)):
        axs[i].hist(lengths, bins=10, alpha=0.5)
        axs[i].set_title(f'Grade {grade}')
        axs[i].set_ylabel('Frequency')
        axs[i].grid(True)

    plt.xlabel('Policy Length')
    plt.suptitle('Distribution of Policy Lengths by Grade')
    plt.show()


#graph_grade_by_whitelist()


def shannon_entropy(probabilities):
    entropy = 0
    for p in probabilities:
        if p != 0:
            entropy -= p * math.log2(p)
    return entropy

def graph_grade_by_policy_frequency():
    grade = grading_function()
    
    grade_list = grade[2]
    grades = ['A', 'B', 'C', 'D', 'F']

    #vals_by_row = get_vals_by_row_all()[0]

    vals_by_row = get_full_csp()[0]

    delete_substr = ['*.', 'www.', 'https://', 'wss://', "ws://", "ssl.", ":*"]

    """
    for j in range(len(vals_by_row)):
        if vals_by_row[j] != None:
            for i in range(len(vals_by_row[j])):
                for substr in delete_substr:
                    vals_by_row[j][i] = vals_by_row[j][i].replace(substr, "")
    """   

    
    


    i = 0
    while i < len(grade_list):
        if vals_by_row[i] == None:
            vals_by_row.pop(i)
            grade_list.pop(i)
            continue
        i += 1

    for i in range(len(vals_by_row)):
        if len(vals_by_row[i]) > 0:
            if vals_by_row[i][-1] == ';':
                vals_by_row[i] = vals_by_row[i][0:-1]

    #for i in range(5):
    #    vals_by_row[i] = " ".join(vals_by_row[i])

    policies_by_grade = [[], [], [], [], []]
    for i in range(len(grade_list)):
        if grade_list[i] == "A":
            policies_by_grade[0].append(vals_by_row[i])
        elif grade_list[i] == "B":
            policies_by_grade[1].append(vals_by_row[i])
        elif grade_list[i] == "C":
            policies_by_grade[2].append(vals_by_row[i])
        elif grade_list[i] == "D":
            policies_by_grade[3].append(vals_by_row[i])
        elif grade_list[i] == "F":
            policies_by_grade[4].append(vals_by_row[i])

    policy_freq_by_grade = [[], [], [], [], []]
    for i, policies in enumerate(policies_by_grade):
        count_policies = Counter(policies)
        pol_freq = count_policies.most_common()

        for policy, count in pol_freq:
            policy_freq_by_grade[i].append((policy, count))


    
    
    policy_frequencies = {grade: {} for grade in grades}

    
    for grade, sublist in zip(grades, policy_freq_by_grade):
        for policy, count in sublist:
            policy_frequencies[grade][policy] = count

    
    plt.figure(figsize=(15, 10))

    for i, grade in enumerate(grades, 1):
        plt.subplot(2, 3, i)
        top_policies = sorted(policy_frequencies[grade].items(), key=lambda x: x[1], reverse=True)[:10]
        policies, counts = zip(*top_policies)
        plt.bar(policies, counts, color='skyblue')
        plt.xlabel('Policy')
        plt.ylabel('Frequency')
        plt.title(f'Grade {grade} - Top 10 Policies')
        plt.gca().set_xticks([])

    plt.tight_layout()
    plt.show()

    # table
    with open("top_ten_policies.txt", "w") as file:
        for grade in grades:
            file.write(f"Grade {grade}:\n")
            top_policies = sorted(policy_frequencies[grade].items(), key=lambda x: x[1], reverse=True)[:10]
            for i, (policy, count) in enumerate(top_policies, start=1):
                policy_with_newlines = '\n'.join([policy[j:j+50] for j in range(0, len(policy), 50)])
                file.write(f"{i}. {policy_with_newlines} ({count})\n")
            file.write("-" * 30 + "\n\n")

    ent_by_grade = []
    for grade in grades:
        top_policies = sorted(policy_frequencies[grade].items(), key=lambda x: x[1], reverse=True)[:10]
        total = 0
        for _, count in top_policies:
            total += count

        probs = []
        for _, count in top_policies:
            probs.append(count/total)

        ent_by_grade.append(shannon_entropy(probs))

    for i, grade in enumerate(grades):
        print("Entropy of policies for ", grade, ": ", ent_by_grade[i])




def graph_grade_by_avg_length():
    grade = grading_function()
    
    grade_list = grade[2]
    grades = ['A', 'B', 'C', 'D', 'F']

    vals_by_row = get_vals_by_row_all()[0]

    lengths = []
    for row in vals_by_row:
        if row == None:
            lengths.append(None)
        else:
            lengths.append(len(row))


    i = 0
    while i < len(grade_list):
        if lengths[i] == None:
            lengths.pop(i)
            grade_list.pop(i)
            continue
        i += 1

    policy_lengths = [[], [], [], [], []]
    for i in range(len(grade_list)):
        if grade_list[i] == "A":
            policy_lengths[0].append(lengths[i])
        elif grade_list[i] == "B":
            policy_lengths[1].append(lengths[i])
        elif grade_list[i] == "C":
            policy_lengths[2].append(lengths[i])
        elif grade_list[i] == "D":
            policy_lengths[3].append(lengths[i])
        elif grade_list[i] == "F":
            policy_lengths[4].append(lengths[i])

    averages = [sum(sublist) / len(sublist) for sublist in policy_lengths]

    plt.figure(figsize=(8, 6))
    plt.plot(averages, grades, marker='o', color='skyblue', linestyle='-')

    plt.xlabel('Policy Length')
    plt.ylabel('Grade')
    plt.title('Grades by Average Policy Length')
    plt.grid(True)
    plt.gca().invert_yaxis()  
    plt.show()


#graph_grade_by_avg_length()

# Use this to test the grading
def show_grades():
    ret = grading_function()

    grades = ret[2]
    descs = ret[4]
    urls = ret[1]

    """
    burls = []
    for i, score in enumerate(grades):
        if score == "B":
            burls.append(urls[i])
            print(urls[i])
            print(descs[i])
    """
    
    """
    aurls = []
    for i, score in enumerate(grades):
        if score == "A":
            aurls.append(urls[i])
    """     
    

    """
    furls = []
    for i, score in enumerate(grades):
        if score == "F":
            furls.append(urls[i])
            print(urls[i])
            print(descs[i])
            print()
    """

    for row in db_list:
        if "default-src 'self' 'unsafe-inline'" in row["csp_data"]:
            for i, desc in enumerate(descs):
                if row['url'] == urls[i]:
                    print(urls[i])
                    print(row['csp_data'])
                    print(desc)
                    print(grades[i])
                    print()
                    

