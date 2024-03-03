from seleniumwire import webdriver
from selenium.webdriver.common.by import By
import csv
import sqlite3
import os
import re
import time

import collecttls
import enrollment

#test_users = ["testuser@gmail.com", "testuser1@gmail.com", "david1", "ยศกร", "ahmet"]
test_users = ["testuser2@gmail.com"]

db_attributes = ["sso_check TEXT","tls_version TEXT","cipher_suite TEXT", "certificate_authority TEXT", "tls_error TEXT", ]

skipped = 0
login_found = 0

def lookforlogin(driver):

    # look for elements containing URLs on the current site
    try:
        hits = driver.find_elements(By.XPATH, "//a[@href]")
    except Exception as e:
        print(f"an exception has occured, while finding nodes: {e}")
        return False

    # collect URLs into list links
    links=[]
    for elem in hits:
        try:
            links.append(elem.get_attribute("href").lower())
        except Exception as e:
            print(f"an exception has occured, the href attribute was not found: {e}")


    # Look for login signifiers in collected URLs
    login_link=''
    for url in links:
        if "login" in url:
            login_link = url
        elif "signin" in url:
            login_link = url

    
    # if a login link is found, go to the address
    # in the case navigation fails, skip
    if login_link != '':
        try:
            driver.get(login_link)
        except Exception as e:
            print(f"The log in link failed to load: {e}")
            return False
        return True, login_link
    

    """
    # in case no login link found, look for log in button, otherwise skip
    try:
        login_button = driver.find_element(By.XPATH, "//div[contains(text(), 'Log in')]")
        login_button.click()
        return True, None
    except Exception as e:
        print(f"log in button not found: {e}")
    """
    
    return False

def parse_csp(csp_data):
    whitelists = []
    usage_unsafe_inline = None
    use_of_wildcards = None
    missing_object_src = None
    usage_strict_dynamic = None
    total_policy_length = 0
    num_nonce = 0
    num_hash = 0
    num_script_src = 0
    num_hash_script_src = 0
    num_nonce_script_src = 0
    num_frame_ancestors = 0
    safe_framing = True
    
    script_src_pattern = re.compile(r'script-src\s+([^;]+)')
    object_src_pattern = re.compile(r'object-src\s+([^;]+)')
    base_uri_pattern = re.compile(r'base-uri\s+([^;]+)')
    default_src_pattern = re.compile(r'default-src\s+([^;]+)')
    frame_src_pattern = re.compile(r'frame-src\s+([^;]+)')
    style_src_pattern = re.compile(r'style-src\s+([^;]+)')
    img_src_pattern = re.compile(r'img-src\s+([^;]+)')
    font_src_pattern = re.compile(r'font-src\s+([^;]+)')
    connect_src_pattern = re.compile(r'connect-src\s+([^;]+)')
    media_src_pattern = re.compile(r'media-src\s+([^;]+)')
    form_action_pattern = re.compile(r'form-action\s+([^;]+)')
    frame_ancestors_pattern = re.compile(r'frame-ancestors\s([^;]+)')

    script_src_match = script_src_pattern.search(csp_data)
    object_src_match = object_src_pattern.search(csp_data)
    base_uri_match = base_uri_pattern.search(csp_data)
    default_src_match = default_src_pattern.search(csp_data)
    frame_src_match = frame_src_pattern.search(csp_data)
    style_src_match = style_src_pattern.search(csp_data)
    img_src_match = img_src_pattern.search(csp_data)
    font_src_match = font_src_pattern.search(csp_data)
    connect_src_match = connect_src_pattern.search(csp_data)
    media_src_match = media_src_pattern.search(csp_data)
    form_action_match = form_action_pattern.search(csp_data)
    frame_ancestors_match = frame_ancestors_pattern.search(csp_data)
    
    if script_src_match:
        script_src_values = script_src_match.group(1).split()
        whitelists.append(script_src_values)
        
        script_src_joined = ' '.join(script_src_values)

        if "unsafe-inline" in script_src_joined:
            usage_unsafe_inline = True
        else:
            usage_unsafe_inline = False

        if "strict-dynamic" in script_src_joined:
            usage_strict_dynamic = True
        else:
            usage_strict_dynamic = False

    
        for val in script_src_values:
            num_script_src += 1

            if "nonce" in val:
                num_nonce += 1

            if "sha256" in val or "sha384" in val or "sha512" in val:
                num_hash += 1

    if not object_src_match and not default_src_match:
        missing_object_src = True
        
    else:
        missing_object_src = False
        
        if object_src_match:
            object_src_values = object_src_match.group(1).split()
            whitelists.append(object_src_values)
        if default_src_match:
            default_src_values = default_src_match.group(1).split()
            whitelists.append(default_src_values)
            
    
    if base_uri_match:
        base_uri_values = base_uri_match.group(1).split()
        whitelists.append(base_uri_values)
    if frame_src_match:
        frame_src_values = frame_src_match.group(1).split()
        whitelists.append(frame_src_values)
    if style_src_match:
        style_src_values = style_src_match.group(1).split()
        whitelists.append(style_src_values)
    if img_src_match:
        img_src_values = img_src_match.group(1).split()
        whitelists.append(img_src_values)
    if font_src_match:
        font_src_values = font_src_match.group(1).split()
        whitelists.append(font_src_values)
    if connect_src_match:
        connect_src_values = connect_src_match.group(1).split()
        whitelists.append(connect_src_values)
    if media_src_match:
        media_src_values = media_src_match.group(1).split()
        whitelists.append(media_src_values)
    if form_action_match:
        form_action_values = form_action_match.group(1).split()
        whitelists.append(form_action_values) 
    if frame_ancestors_match:
        frame_ancestors_values = frame_ancestors_match.group(1)

        for entry in frame_ancestors_values.split():
            num_frame_ancestors += 1

            if entry == "*":
                safe_framing = False
    else:
        frame_ancestors_values = None

    for policy in whitelists:
        for entry in policy:
            total_policy_length += 1

            if entry == "*":
                use_of_wildcards = True

            if "nonce" in entry:
                num_nonce += 1

            if "sha256" in entry or "sha384" in entry or "sha512" in entry:
                num_hash += 1
            
                          
    return usage_unsafe_inline, use_of_wildcards, missing_object_src, frame_ancestors_values, num_frame_ancestors, safe_framing, \
            total_policy_length, num_hash, num_nonce, num_script_src, num_hash_script_src, num_nonce_script_src, usage_strict_dynamic
        

def csp_search(driver):
    csp_data = None
    other_headers = None
    try:
        meta_element = driver.find_element(By.XPATH, "//meta[contains(@http-equiv, 'Content-Security-Policy')]")
    except: 
        meta_element = None

    for request in driver.requests:
        csp_data = request.response.headers.get("content-security-policy")
        if csp_data != None and \
           csp_data != "default-src 'none'; frame-ancestors 'none'; base-uri 'none';" and \
           csp_data != "default-src 'none'; style-src 'unsafe-inline'; sandbox":
            hsts_data = request.response.headers.get("strict-transport-security")
            xframe_data = request.response.headers.get("x-frame-options")
            xxss_data = request.response.headers.get("x-xss-protection")
            referrer_policy = request.response.headers.get("referrer-policy")
            feature_policy = request.response.headers.get("feature-policy")
            cspro_data = request.response.headers.get("content-security-policy-report-only")
            upgrade = request.response.headers.get("upgrade-insecure-requests")
            other_headers = [hsts_data, xframe_data, xxss_data, referrer_policy, feature_policy, cspro_data, upgrade]
            break

    
    if csp_data == None:
        try:
            if meta_element!=None:
                csp_data = meta_element.get_attribute("content")
        except:
            print("No CSP data found in HTML")

    
    return csp_data, other_headers
    
def scrape_header(first_request):
    first_response_head = first_request.response.headers
    csp_data = None
    hsts_data = None
    xframe_data = None
    xxss_data = None
    referrer_policy = None
    feature_policy = None
    cspro_data = None
    upgrade = None
    
    
    csp_data = first_response_head.get("content-security-policy")

    cspro_data = first_response_head.get("content-security-policy-report-only")
    
    hsts_data = first_response_head.get("strict-transport-security")
    
    xframe_data = first_response_head.get("x-frame-options")
    
    xxss_data = first_response_head.get("x-xss-protection")
    
    referrer_policy = first_response_head.get("referrer-policy")
    
    feature_policy = first_response_head.get("feature-policy")

    upgrade = first_response_head.get("upgrade-insecure-requests")
    
    return csp_data, [hsts_data, xframe_data, xxss_data, referrer_policy, feature_policy, cspro_data, upgrade]
    
def collect_header(driver):
    first_request = driver.requests[0]
    
    csp_data, other_headers = scrape_header(first_request)
    
    csp_data_new = None
    if csp_data == None or \
       csp_data == "default-src 'none'; frame-ancestors 'none'; base-uri 'none';" or \
       csp_data == "default-src 'none'; style-src 'unsafe-inline'; sandbox":
        try:
            csp_data_new, other_headers_new = csp_search(driver)
        except:
            print("no csp data found or csp update failed")
        finally:
            if csp_data_new:
                csp_data = csp_data_new
                other_headers = other_headers_new

    
    if csp_data != None:
        usage_unsafe_inline, use_of_wildcards, missing_object_src, frame_ancestors_values, num_frame_ancestors, safe_framing, \
            total_policy_length, num_hash, num_nonce, num_script_src, num_hash_script_src, num_nonce_script_src, usage_strict_dynamic = parse_csp(csp_data)
    else:
        usage_unsafe_inline, use_of_wildcards, missing_object_src, frame_ancestors_values, num_frame_ancestors, safe_framing, \
            num_hash, num_nonce, num_script_src, num_hash_script_src, num_nonce_script_src, usage_strict_dynamic = \
                None, None, None, None, None, None, None, None, None, None, None, None, None

    if other_headers[0] != None:
        supports_hsts = True
        hsts_data = other_headers[0]
    else:
        supports_hsts = False
        hsts_data = None

    if other_headers[1] != None:
        supports_xframe = True
        xfo_data = other_headers[1]
    else:
        supports_xframe = False
        xfo_data = None

    if other_headers[2] != None:
        supports_xxss = True
        xxss_data = other_headers[2]
    else:
        supports_xxss = False
        xxss_data = None
        
    #supports_referrer_policy = False
    #for s in ["no-referrer", "strict-origin-when-cross-origin", "same-origin", "origin"]:
            
    if other_headers[3] != None:
        supports_referrer_policy = True
        referrer_data = other_headers[3]
    else: 
        supports_referrer_policy = False
        referrer_data = None

    if other_headers[4] != None:
        supports_feature_policy = True
        feature_data = other_headers[4]
    else:
        supports_feature_policy = False
        feature_data = None

    if other_headers[5] != None:
        supports_cspro = True
    else:
        supports_cspro = False

    if other_headers[6] != None:
        if "1" in other_headers[6]:
            supports_upgrade = True
        else:
            supports_upgrade = False
    else:
        supports_upgrade = False

    

    
    return csp_data, usage_unsafe_inline, use_of_wildcards, missing_object_src, frame_ancestors_values, num_frame_ancestors, safe_framing, \
            total_policy_length, num_hash, num_nonce, num_script_src, num_hash_script_src, num_nonce_script_src, usage_strict_dynamic, \
             supports_hsts, hsts_data, supports_xframe, xfo_data, supports_xxss, xxss_data, \
              supports_referrer_policy, referrer_data, supports_feature_policy, feature_data, supports_cspro, supports_upgrade

def scrape_password_requests(driver, email):
    requests = driver.requests
    password = "WillMarc5567"
   
    message_found = False
    sent_in_plaintext = False
    post_pass = None
    get_pass = None
    possible_post_request = []
    possible_get_request = []

    get_rqs = []
    post_rqs = [] 
    
    for request in requests:
        if request.method == "POST" and b"password" in request.body \
           and (b"name" in request.body or b"email" in request.body):
            possible_post_request.append(request)
            
        elif request.method == "POST" and b"pw" in request.body \
           and (b"name" in request.body or b"email" in request.body):
            possible_post_request.append(request)

        elif request.method == "GET" and "password" in request.url \
             and ("name" in request.url or "email" in request.url):
            possible_get_request.append(request)
            
        elif request.method == "GET" and "pw" in request.url \
             and ("name" in request.url or "email" in request.url):
            possible_get_request.append(request)

        elif request.method == "POST" and \
            (bytes(password, 'utf-8') in request.body or bytes(email, 'utf-8')):
            possible_post_request.append(request)

        elif request.method == "GET" and \
             (password in request.url or email in request.url):
            possible_get_request.append(request)


    for request in possible_post_request:
        if bytes(password, 'utf-8') in request.body or bytes(email, 'utf-8') in request.body:
            post_pass = request
            post_rqs.append(request)
            message_found = True

            #print(request.url)
            #print("password in plain:" + str(bytes(password, 'utf-8') in request.body))
            #print("username in plain:" + str(bytes(email.split('@')[0], 'utf-8') in request.body))

            if bytes(password, 'utf-8') in request.body:
                sent_in_plaintext = True
                break
            else:
                sent_in_plaintext = False

    for request in possible_get_request:
        if password in request.url or email in request.url:
            get_pass = request
            get_rqs.append(request)
            message_found = True

            if password in request.url:
                sent_in_plaintext = True
                break
            else:
                sent_in_plaintext = False


    if post_pass == None and get_pass == None:
        request_type = "Not Found"
    elif post_pass != None:
        request_type = "POST"
    elif get_pass != None:
        request_type = "GET"
    else:
        request_type = "Both"
    

    return message_found, request_type, sent_in_plaintext, post_pass, get_pass, post_rqs, get_rqs

def find_next(driver):
    next_buttons = []

    tags = ["input", "button", "span"]
    attributes = ["text()"]
    values = ["CONTINUE", "NEXT"]

    
    for tag in tags:
        for attr in attributes:
            for val in values:
                xpath_query = f"//{tag}[contains(translate({attr}, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), '{val}')]"
                try:
                    found_buttons = driver.find_elements(By.XPATH, xpath_query)
                    next_buttons.extend(found_buttons)
                except:
                    None


    #print("next_button", len(next_buttons))
    return next_buttons

def find_username_input(driver):
        
        username_fields = []
        tags = ["input", "div"]
        attributes = ["*","name","id","aria-label","type", "autocomplete"]
        values = ["USERNAME", "EMAIL"]

        for tag in tags:
            for attr in attributes:
                for val in values:
                    xpath_query = f"//{tag}[contains(translate(@{attr}, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'{val}')]"
                    try:
                        found_fields = driver.find_elements(By.XPATH, xpath_query)
                        username_fields.extend(found_fields)
                    except:
                        None

        #print("username field:", len(username_fields))
        
        return username_fields
        
def find_password_input(driver):
    try:
        password_fields = driver.find_elements(By.XPATH,"//input[@type='password']")
        #print("password field:", len(password_fields))
        return password_fields
    except:
        return []

def find_login(driver):
    login_buttons = []

    tags = ["div", "button", "input"]
    attributes = ["text()", "@value"]
    values = ["LOG IN", "SIGN IN", "LOGIN", "SIGNIN"]

    
    for tag in tags:
        for attr in attributes:
            for val in values:
                xpath_query = f"//{tag}[contains(translate({attr}, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), '{val}')]"
                try:
                    found_buttons = driver.find_elements(By.XPATH, xpath_query)
                    login_buttons.extend(found_buttons)
                except:
                    None

    #print("login button:", len(login_buttons))
    return login_buttons

def attempt_login(driver, user):
    password = "WillMarc5567?!"

    # Look for next buttons, username inputs
    username_inputs = find_username_input(driver)

    if username_inputs == None:
        print("No username/email fields found")
        driver.quit()
        return

    next_buttons = find_next(driver)
    
    # enter username
    for ufield in username_inputs:
        try:
            ufield.clear()
            ufield.send_keys(user)
            break
        except:
            print("username fill failed")
        
        time.sleep(.24)
    
    
    # try to press next buttons
    for button in next_buttons:
        try:
            button.click()
        except Exception as e:
            print(f"click failed: {e}")

        time.sleep(.13)
    
    # wait for loading
    time.sleep(5)

    # now on final log in screeen, look for password inputs
    password_inputs = find_password_input(driver)
    
    for pfield in password_inputs:
        try:
            pfield.clear()
            pfield.send_keys(password)
            break
        except:
            print("fill failed")
        
        time.sleep(.23)

    
    # now on final screen log in screen, look for log in buttons
    login_buttons = find_login(driver)

    # try to press log in buttons
    for button in login_buttons:
        try:
            button.click()
            time.sleep(.12)
        except Exception as e:
            print("click failed:", e)

    return len(password_inputs)

def create_db_row(url,cursor,connection):
    
    #look for website entries in db that have id = to current URL
    cursor.execute("SELECT * FROM websites WHERE url = ?", (url,))

    #if there is no matches, create entry
    if cursor.fetchone() is None:
        insertion_string = "INSERT INTO websites VALUES ('"+url+"'"
        for attribte in db_attributes:
            insertion_string+= ",'N/A'"
        insertion_string +=  ")"
        cursor.execute(insertion_string)
        print("Added "+url+" into database")
    #if there is, the url is already an entry in the database
    else:
       print(url+" already exists in table")
    connection.commit()

def add_to_db(row, data_dict, cursor, connection):

    create_db_row(row, cursor, connection)

    # add sso to database
    cursor.execute('UPDATE websites SET sso_check = ? WHERE url = ?', (data_dict["sso_check"], row))
    connection.commit()
    print("Updated "+row+" to SSO: "+data_dict["sso_check"])



    # add tls to database
    cursor.execute('UPDATE websites SET tls_version = ? WHERE url = ?', (data_dict["tls_version"], row))
    cursor.execute('UPDATE websites SET cipher_suite = ? WHERE url = ?', (data_dict["cipher_suite"], row))
    cursor.execute('UPDATE websites SET certificate_authority = ? WHERE url = ?', (data_dict["certificate_authority"], row))
    cursor.execute('UPDATE websites SET tls_error = ? WHERE url = ?', (data_dict["tls_error"], row))
    connection.commit()
    print("Updated "+row+" to Cipher Suite: "+data_dict["cipher_suite"] )
    print("Updated "+row+" to TLS Version: "+data_dict["tls_version"] )
    print("Updated "+row+" to TLS Version: "+data_dict["tls_failed"] )


    # add response header info to database
    print("Header collection failed: "+data_dict["header_failed"])
        #header_failed
    cursor.execute('UPDATE websites SET header_failed = ? WHERE url = ?', (data_dict["header_failed"], row))

    print("CSP Data: "+data_dict["csp_data"])
        #csp_data
    cursor.execute('UPDATE websites SET csp_data = ? WHERE url = ?', (data_dict["csp_data"], row))

    print("CSP Check--------------------------------------")

    print("Allows inline scripts:" + data_dict["usage_unsafe_inline"])
        #inline_script
    cursor.execute('UPDATE websites SET usage_unsafe_inline = ? WHERE url = ?', (data_dict["usage_unsafe_inline"], row))

    print("At least one directive allows wildcards:" + data_dict["use_of_wildcards"])
        #wildcard
    cursor.execute('UPDATE websites SET wildcard = ? WHERE url = ?', (data_dict["use_of_wildcards"], row))

    print("Lacks directives for object source:" + data_dict["missing_object_src"])
        #missing_object_src
    cursor.execute('UPDATE websites SET missing_object_src = ? WHERE url = ?', (data_dict["missing_object_src"], row))

    print("Frame ancestors data: "+data_dict["frame_ancestors_data"])
        #frame_ancestors_data
    cursor.execute('UPDATE websites SET frame_ancestors_data = ? WHERE url = ?', (data_dict["frame_ancestors_data"], row))

    print("Number of frame ancestors:"+data_dict["num_frame_ancestors"])
        #num_frame_ancestors
    cursor.execute('UPDATE websites SET num_frame_ancestors = ? WHERE url = ?', (data_dict["num_frame_ancestors"], row))

    print("Has safe framing policy in CSP:" + data_dict["safe_framing"])
        #safe_framing
    cursor.execute('UPDATE websites SET safe_framing = ? WHERE url = ?', (data_dict["safe_framing"], row))

    print("Total policy length: "+data_dict["total_policy_length"])
        #total_policy_length
    cursor.execute('UPDATE websites SET total_policy_length = ? WHERE url = ?', (data_dict["total_policy_length"], row))

    print("Total number of hashes: "+data_dict["num_hash"])
        #num_hash
    cursor.execute('UPDATE websites SET num_hash = ? WHERE url = ?', (data_dict["num_hash"], row))

    print("Total number of nonces: "+data_dict["num_nonce"])
        #num_nonce
    cursor.execute('UPDATE websites SET num_nonce = ? WHERE url = ?', (data_dict["num_nonce"], row))

    print("script-src number of hashes: "+data_dict["num_hash_script_src"])
        #num_hash_script_src
    cursor.execute('UPDATE websites SET num_hash_script_src = ? WHERE url = ?', (data_dict["num_hash_script_src"], row))

    print("script-src number of nonces: "+data_dict["num_nonce_script_src"])
        #num_nonce_script_src
    cursor.execute('UPDATE websites SET num_nonce_script_src = ? WHERE url = ?', (data_dict["num_nonce_script_src"], row))

    print("Usage of strict-dynamic: "+data_dict["usage_strict_dynamic"])
        #usage_strict_dynamic
    cursor.execute('UPDATE websites SET usage_strict_dynamic = ? WHERE url = ?', (data_dict["usage_strict_dynamic"], row))

    print("Other security headers--------------------------")

    print("Enforces HTTP Strict Transport Security:" + data_dict["supports_hsts"])
        #hsts
    cursor.execute('UPDATE websites SET supports_hsts = ? WHERE url = ?', (data_dict["supports_hsts"], row))

    print("HSTS data: "+data_dict["hsts_data"])
        #hsts_data
    cursor.execute('UPDATE websites SET hsts_data = ? WHERE url = ?', (data_dict["hsts_data"], row))

    print("Enforces x-frame-options:" + data_dict["supports_xframe"])
        #supports_xframe
    cursor.execute('UPDATE websites SET supports_xframe = ? WHERE url = ?', (data_dict["supports_xframe"], row))

    print("XFO data: "+data_dict["xfo_data"])
        #XFO_data
    cursor.execute('UPDATE websites SET xfo_data = ? WHERE url = ?', (data_dict["xfo_data"], row))

    print("x-xss-protection exists:" + data_dict["supports_xxss"])
        #xxss
    cursor.execute('UPDATE websites SET supports_xxss = ? WHERE url = ?', (data_dict["supports_xxss"], row))

    print("x-xss data: "+data_dict["xxss_data"])
        #xxss_data
    cursor.execute('UPDATE websites SET xxss_data = ? WHERE url = ?', (data_dict["xxss_data"], row))

    print("Has referrer policy:" + data_dict["supports_referrer_policy"])
        #supports_referrer_policy
    cursor.execute('UPDATE websites SET supports_referrer_policy = ? WHERE url = ?', (data_dict["supports_referrer_policy"], row))

    print("Referrer policy data: "+data_dict["referrer_data"])
        #referrer_data
    cursor.execute('UPDATE websites SET referrer_data = ? WHERE url = ?', (data_dict["referrer_data"], row))

    print("Feature policy exists:" + data_dict["supports_feature_policy"])
        #feature_policy
    cursor.execute('UPDATE websites SET supports_feature_policy = ? WHERE url = ?', (data_dict["supports_feature_policy"], row))

    print("Feature policy data: "+data_dict["feature_data"])
        #feature_data
    cursor.execute('UPDATE websites SET feature_data = ? WHERE url = ?', (data_dict["feature_data"], row))

    print("cspro exists: "+data_dict["supports_cspro"])
        #supports_cspro
    cursor.execute('UPDATE websites SET supports_cspro = ? WHERE url = ?', (data_dict["supports_cspro"], row))

    print("upgrade-insecure-reuests exists: "+data_dict["supports_upgrade"])
        #supports_upgrade
    cursor.execute('UPDATE websites SET supports_upgrade = ? WHERE url = ?', (data_dict["supports_upgrade"], row))


    connection.commit()
    print("Updated "+row+" HTTP header and CSP information")

    print("--HTTP Password Submission--")
    print("Message Found: "+data_dict["message_found"])
        #pass_message_found
    cursor.execute('UPDATE websites SET pass_message_found = ? WHERE url = ?', (data_dict["message_found"], row))

    print("Sent in Plaintext: "+data_dict["sent_in_plaintext"])
        #pass_plaintext
    cursor.execute('UPDATE websites SET pass_plaintext = ? WHERE url = ?', (data_dict["sent_in_plaintext"], row))
    
    print("Request type: "+data_dict["request_type"])
        #pass_request_type
    cursor.execute('UPDATE websites SET pass_request_type = ? WHERE url = ?', (data_dict["request_type"], row))

    print("Found POST request: ")
    print(f"Keywords found in POST Request URL: " +data_dict["post_pass"].url)
    print(f"POST Request Headers:"+ data_dict["post_pass"].headers)
    print(f"POST Request Body:" +data_dict["post_pass"].body)
        #post_pass
    cursor.execute('UPDATE websites SET post_pass = ? WHERE url = ?', (data_dict["post_pass"], row))

    print("Found GET request: ")
    print(f"Keywords found in GET Request URL:"+ data_dict["get_pass"].url)
    print(f"GET Request Headers:" +data_dict["get_pass"].headers)
        #get_pass
    cursor.execute('UPDATE websites SET get_pass = ? WHERE url = ?', (data_dict["get_pass"], row))

    print("Sign in failed: "+data_dict["sign_in_failed"])
        #sign_in_failed
    cursor.execute('UPDATE websites SET sign_in_failed = ? WHERE url = ?', (data_dict["sign_in_failed"], row))

    connection.commit()

    print("Updated "+row+" password request information")

    return



def run_tests(row, cursor, connection):
    global skipped
    global login_found

    data_dict = {"sso_check" : "NA","tls_version" : "NA", "cipher_suite" : "NA", "certificate_authority" : "NA", "tls_error" : "NA", \
                 "header_failed" : "NA", "csp_data" : "NA", "usage_unsafe_inline" : "NA", "use_of_wildcards" : "NA", "missing_object_src" : "NA", \
                 "frame_ancestors_data" : "NA", "num_frame_ancestors" : "NA", "safe_framing" : "NA", "total_policy_length" : "NA", \
                 "num_hash" : "NA", "num_nonce" : "NA", "num_script_src" : "NA", "num_hash_script_src" : "NA", "num_nonce_script_src" : "NA", \
                 "usage_strict_dynamic" : "NA", "supports_hsts" : "NA", "hsts_data" : "NA", "supports_xframe" : "NA", "xfo_data" : "NA", \
                 "supports_xxss" : "NA", "xxss_data" : "NA", "supports_referrer_policy" : "NA", "referrer_data" : "NA", \
                 "supports_feature_policy" : "NA", "feature_data" : "NA", "supports_cspro" : "NA", "supports_upgrade" : "NA", \
                 "message_found" : "NA", "request_type" : "NA", "sent_in_plaintext" : "NA", "post_pass" : "NA", "get_pass" : "NA", \
                 "sign_in_failed" : "NA"}

    print("Current Website:", row)
    
    # open web driver for current entry
    driver = webdriver.Firefox()
        
    cur = "https://" + row

    # try to navigate to page
    # except close driver, skip
    try:
        driver.get(cur)
    except Exception as e:
        driver.quit()
        skipped += 1
        print(f"an exception has occured, the site did not connect: {e}")
        return
    
    # wait for page to load
    time.sleep(2)

    # look for login links and get
    found, login_link = lookforlogin(driver)

    time.sleep(3)

    # in case login links not found, skip
    if not found:
        
        print("sign in link not found")

        login_buttons = lookforlogin(driver)
        num_buttons = len(login_buttons)

        for button in login_buttons:
            try:
                button.click()
            except:
                num_buttons -= 1
                print("click failed")
            
            time.sleep(.25)

        if num_buttons == 0:
            # Add mode for manual here
            print("log in button not found")
            driver.quit()
            return
    else:
        login_found += 1
        
    #check for sso
    sso_exists = enrollment.sso_check(driver)
    data_dict["sso_check"] = sso_exists
    print("sso exists:", sso_exists)

    
    # collect tls information
    tls_version, cipher_suite, authority, tls_failed = None, None, None, False
    try:
        tls_version, cipher_suite, authority = collecttls.get_tls_info(cur)

        data_dict["tls_version"] = tls_version
        data_dict["cipher_suite"] = cipher_suite
        data_dict["authority"] = authority

        print("TLS version:" + tls_version)
        print("Cipher suite:" + cipher_suite[0])
        print("CA:", authority)

    except Exception as e:
        tls_failed = e

        data_dict["tls_error"] = tls_failed

        print(f"TLS test failed: {e}")

    # collect header information
    header_failed = False
    try:
       csp_data, usage_unsafe_inline, use_of_wildcards, missing_object_src, frame_ancestors_values, num_frame_ancestors, safe_framing, \
            total_policy_length, num_hash, num_nonce, num_script_src, num_hash_script_src, num_nonce_script_src, usage_strict_dynamic, \
             supports_hsts, hsts_data, supports_xframe, xfo_data, supports_xxss, xxss_data, \
              supports_referrer_policy, referrer_data, supports_feature_policy, feature_data, supports_cspro, supports_upgrade = collect_header(driver)
    except Exception as e:
        print(f"header collection failed: {e}")
        header_failed = True

    if header_failed:
        data_dict["header_failed"] = "True"
    else:
        data_dict["header_failed"] = "False"
        data_dict["csp_data"] = csp_data
        data_dict["usage_unsafe_inline"] = usage_unsafe_inline
        data_dict["use_of_wildcards"] = use_of_wildcards
        data_dict["missing_object_src"] = missing_object_src
        data_dict["frame_ancestors_data"] = frame_ancestors_values
        data_dict["num_frame_ancestors"] = num_frame_ancestors
        data_dict["safe_framing"] = safe_framing
        data_dict["total_policy_length"] = total_policy_length
        data_dict["num_hash"] = num_hash
        data_dict["num_nonce"] = num_nonce
        data_dict["num_script_src"] = num_script_src
        data_dict["num_hash_script_src"] = num_hash_script_src
        data_dict["num_nonce_script_src"] = num_nonce_script_src
        data_dict["usage_strict_dynamic"] = usage_strict_dynamic
        data_dict['supports_hsts'] = supports_hsts
        data_dict["hsts_data"] = hsts_data
        data_dict["supports_xframe"] = supports_xframe
        data_dict["xfo_data"] = xfo_data
        data_dict["supports_xxss"] = supports_xxss
        data_dict["xxss_data"] = xxss_data
        data_dict["supports_referrer_policy"] = supports_referrer_policy
        data_dict["referrer_data"] = referrer_data
        data_dict["supports_feature_policy"] = supports_feature_policy
        data_dict["feature_data"] = feature_data
        data_dict["supports_cspro"] = supports_cspro
        data_dict["supports_upgrade"] = supports_upgrade

    # HTTP password submission
    pass_fields = None

    message_found, request_type, sent_in_plaintext, post_pass, get_pass, post_rqs, get_rqs = None, None, None, None, None, None, None

    for user in test_users:
        pass_fields = attempt_login(driver, user)

        # wait for messages to be sent
        time.sleep(5)

    
        # look for password carrying http requests
        message_found, request_type, sent_in_plaintext, post_pass, get_pass, post_rqs, get_rqs = scrape_password_requests(driver, user)

        if message_found == False:
                driver.get(login_link)
                time.sleep(2)
        else:
            break


    data_dict["message_found"] = message_found

    if message_found:
        data_dict["request_type"] = request_type

    if post_pass:
        data_dict["post_pass"] = post_pass
    
    if get_pass:
        data_dict["get_pass"] = get_pass


    if not message_found or pass_fields == 0:
        signin_failed = True
    else:
        signin_failed = False

    
    data_dict["sign_in_failed"] = signin_failed

    driver.quit()

    print("Allows inline scripts:" + data_dict["usage_unsafe_inline"])
    print("At least one directive allows wildcards:" + data_dict["use_of_wildcards"])
    print("Lacks directives for object source:" + data_dict["missing_object_src"])
    print("Total policy length: "+data_dict["total_policy_length"])
    print("script-src number of hashes: "+data_dict["num_hash_script_src"])
    print("script-src number of nonces: "+data_dict["num_nonce_script_src"])
    print("Usage of strict-dynamic: "+data_dict["usage_strict_dynamic"])
    print("Enforces HTTP Strict Transport Security:" + data_dict["supports_hsts"])
    print("Enforces x-frame-options:" + data_dict["supports_xframe"])
    print("XFO data: "+data_dict["xfo_data"])
    print("x-xss-protection exists:" + data_dict["supports_xxss"])
    print("x-xss data: "+data_dict["xxss_data"])
    print("Message Found: "+data_dict["message_found"])
    print("Sent in Plaintext: "+data_dict["sent_in_plaintext"])
    print("Found POST request: ")
    print(f"Keywords found in POST Request URL: " +data_dict["post_pass"].url)
    print(f"POST Request Headers:"+ data_dict["post_pass"].headers)
    print(f"POST Request Body:" +data_dict["post_pass"].body)
    print("Found GET request: ")
    print(f"Keywords found in GET Request URL:"+ data_dict["get_pass"].url)
    print(f"GET Request Headers:" +data_dict["get_pass"].headers)
    print("Sign in failed: "+data_dict["sign_in_failed"])

    #add_to_db(row, data_dict, cursor, connection)

    
    
    
    











    

     

    
    



    




def auto_collect():
    with open("top-1m.csv", newline='') as file:
        lineread = csv.reader(file, delimiter = ',')

        cwd = os.getcwd()
        connection = sqlite3.connect(cwd+"/db/test2.db")
        cursor = connection.cursor()

        creation_string =("CREATE TABLE IF NOT EXISTS websites (url TEXT PRIMARY KEY")
        for entry in db_attributes:
            creation_string+=(", "+entry)
        
        creation_string+=");"
        cursor.execute(creation_string)
        connection.commit()
        
        ct = 0
        rows = 500
        for row in lineread:
            if ct < rows:
                try:
                    run_tests(row[1], cursor, connection)
                except:
                    print("moving on to next site\n")
            else:
                break

auto_collect()