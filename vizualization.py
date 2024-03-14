import os
import sqlite3
import matplotlib
import re
import matplotlib.pyplot as plt
from collections import Counter
import numpy as np

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
      

#Distribution among csp directives
        


#usage of csp, cspro
        


#distribution of whitelisted domains
        

#tls version

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

        

