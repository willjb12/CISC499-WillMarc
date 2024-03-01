from seleniumwire import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.firefox.options import Options
from urllib.parse import urlparse
import csv
import sqlite3
import os
import re
import time

import collecttls
import enrollment

db_attributes = []

def lookforlogin(driver):

    # look for elements containing URLs on the current site
    try:
        hits = driver.find_elements(By.XPATH, "//a[@href]")
    except Exception as e:
        print(f"an exception has occured, while finding nodes: {e}")
        return False, None

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
        return True
    

    
    # in case no login link found, look for log in button, otherwise skip
    try:
        login_button = driver.find_element(By.XPATH, "//div[contains(text(), 'Log in')]")
        login_button.click()
        return True
    except Exception as e:
        print(f"log in button not found: {e}")

    return False

def parse_csp(csp_data):
    whitelists = []
    usage_unsafe_inline = None
    use_of_wildcards = None
    missing_object_src = None
    usage_strict_dynamic = None
    safe_framing = False
    total_policy_length = 0
    num_nonce = 0
    num_hash = 0
    
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

        if "unsafe-inline" in script_src_joined and "nonce" not in script_src_joined and 'strict-dynamic' not in script_src_joined and "hash" not in script_src_joined:
            usage_unsafe_inline = True
        else:
            usage_unsafe_inline = False

        if "strict-dynamic" in script_src_joined:
            usage_strict_dynamic = True
        else:
            usage_strict_dynamic = False


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
        frame_ancestors_values = frame_ancestors_match.group()

    for policy in whitelists:
        total_policy_length -= 1
        for entry in policy:
            total_policy_length += 1

            if entry == "*":
                use_of_wildcards = True

            if "nonce" in entry:
                num_nonce += 1

            if "sha256" in entry or "sha384" in entry or "sha512" in entry:
                num_hash += 1
            

    if frame_ancestors_match:
        if '*' not in frame_ancestors_values:
            safe_framing = True
        else:
            safe_framing = False
                          
    return usage_unsafe_inline, use_of_wildcards, missing_object_src, safe_framing, num_hash, num_nonce, usage_strict_dynamic
        

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
            other_headers = [hsts_data, xframe_data, xxss_data, referrer_policy, feature_policy]
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
    
    
    csp_data = first_response_head.get("content-security-policy")
    
    hsts_data = first_response_head.get("strict-transport-security")
    
    xframe_data = first_response_head.get("x-frame-options")
    
    xxss_data = first_response_head.get("x-xss-protection")
    
    referrer_policy = first_response_head.get("referrer-policy")
    
    feature_policy = first_response_head.get("feature-policy")
    
    return csp_data, [hsts_data, xframe_data, xxss_data, referrer_policy, feature_policy]
    
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
        usage_unsafe_inline, use_of_wildcards, missing_object_src, safe_framing, num_hash, num_nonce, usage_strict_dynamic = parse_csp(csp_data)
    else:
        usage_unsafe_inline, use_of_wildcards, missing_object_src, safe_framing, num_hash, num_nonce, usage_strict_dynamic = None, None, None, None, None, None, None

    if other_headers[0] != None:
        supports_hsts = True
    else:
        supports_hsts = False

    if other_headers[1] != None:
        supports_xframe = True

        print("XFO: " + other_headers[1])
    else:
        supports_xframe = False

    if other_headers[2] != None:
        supports_xxss = True

        print("X-xss: " + other_headers[2])
    else:
        supports_xxss = False
        
    #supports_referrer_policy = False
    #for s in ["no-referrer", "strict-origin-when-cross-origin", "same-origin", "origin"]:
            
    if other_headers[3] != None:
        supports_referrer_policy = True

        print("Referer-policy: " + other_headers[3])
    else: 
        supports_referrer_policy = False
            

    if other_headers[4] != None:
        supports_feature_policy = True
    else:
        supports_feature_policy = False

    

    
    return csp_data,usage_unsafe_inline, use_of_wildcards, missing_object_src, safe_framing, num_hash, num_nonce, usage_strict_dynamic, \
            supports_hsts, supports_xframe, supports_xxss, supports_referrer_policy, supports_feature_policy

def scrape_password_requests(driver):
    requests = driver.requests
    password = "WillMarc5567"
    email = "testuser"
   
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


    print("next_button", len(next_buttons))
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

        print("username field:", len(username_fields))
        
        return username_fields
        
def find_password_input(driver):
    try:
        password_fields = driver.find_elements(By.XPATH,"//input[@type='password']")
        print("password field:", len(password_fields))
        return password_fields
    except:
        return []

def find_login(driver):
    login_buttons = []

    tags = ["div", "button"]
    attributes = ["text()"]
    values = ["LOG IN", "SIGN IN"]

    
    for tag in tags:
        for attr in attributes:
            for val in values:
                xpath_query = f"//{tag}[contains(translate({attr}, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), '{val}')]"
                try:
                    found_buttons = driver.find_elements(By.XPATH, xpath_query)
                    login_buttons.extend(found_buttons)
                except:
                    None

    print("login button:", len(login_buttons))
    return login_buttons

def run_tests(row, cursor, connection):

    print("Current Website:", row)
    
    # open web driver for current entry
    driver = webdriver.Firefox()
        
    cur = "https://www." + row

    # try to navigate to page
    # except close driver, skip
    try:
        driver.get(cur)
    except Exception as e:
        driver.quit()
        print(f"an exception has occured, the site did not connect: {e}")
        return
    
    # wait for page to load
    time.sleep(2)

    # look for login links and get
    found = lookforlogin(driver)

    time.sleep(2)


    # in case login links not found, skip
    if not found:
        # Add mode for manual here
        print("sign in not found")
        driver.quit()
        return
    
    # collect tls information
    tls_version, cipher_suite, tls_failed = None, None, None
    try:
        tls_version, cipher_suite = collecttls.get_tls_info(cur)
        print("TLS version:" + tls_version)
        print("Cipher suite:" + cipher_suite[0])
    except Exception as e:
        tls_failed = e
        print(f"TLS test failed: {e}")

    # collect header information
    try:
       csp_data,usage_unsafe_inline, use_of_wildcards, missing_object_src, safe_framing, num_hash, num_nonce, usage_strict_dynamic, \
            supports_hsts, supports_xframe, supports_xxss, supports_referrer_policy, supports_feature_policy = collect_header(driver)
    except Exception as e:
        print(f"header collection failed: {e}")


    # HTTP password submission

    test_users = ["testuser@gmail.com", "testuser1", "testuser@gmail.com"]
    password = "WillMarc5567!?"

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
                ufield.send_keys(test_users[0])
                time.sleep(.24)
        
            except:
                print("fill failed")
                driver.quit()
                return
    
    
    # try to press next buttons
    for button in next_buttons:
        try:
            button.click()
            time.sleep(.13)
        except Exception as e:
            print(f"click failed: {e}")
    
    # wait for loading
    time.sleep(5)

    # now on final log in screeen, look for password inputs
    password_inputs = find_password_input(driver)
    
    for pfield in password_inputs:
            try:
                pfield.clear()
                pfield.send_keys(password)
                time.sleep(.23)
            except:
                print("fill failed")
                driver.quit()
                return
    
    # now on final screen log in screen, look for log in buttons
    login_buttons = find_login(driver)

    # try to press log in buttons
    for button in login_buttons:
        try:
            button.click()
            time.sleep(.12)
        except Exception as e:
            print("click failed:", e)
    
    # wait for messages to be sent
    time.sleep(10)

    
    # look for password carrying http requests
    message_found, request_type, sent_in_plaintext, post_pass, get_pass, post_rqs, get_rqs = scrape_password_requests(driver)

    if post_pass:
        print("Post Message:")
        print(f"Keywords found in POST Request URL: {post_pass.url}")
        print(f"POST Request Headers: {post_pass.headers}")
        print(f"POST Request Body: {post_pass.body}")
    
    if get_pass:
        print("Get Message:")
        print(f"Keywords found in GET Request URL: {get_pass.url}")
        print(f"GET Request Headers: {get_pass.headers}")

    print("message_found:", message_found)
    print("Found in plaintext:", sent_in_plaintext)

    if password_inputs == 0:
        signin_failed = True
    else:
        signin_failed = False

    driver.quit()

    
    
    
    











    

     

    
    



    




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

run_tests("twitter.com", None, None)