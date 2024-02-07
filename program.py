from seleniumwire import webdriver
from selenium.webdriver.common.by import By
import time
import tkinter as tk
import sqlite3
import os
import enrollment
import collectheader
import emailverification
import http_passwordsubmission
import collecttls
import csv
from urllib.parse import urlparse

websites = ["https://www.instagram.com/","https://pinterest.com","https://reddit.com","https://facebook.com","https://amazon.ca","https://twitter.com","https://wikipedia.org","https://yahoo.com","https://tiktok.com"]





db_attributes = ["sso_check TEXT","tls_version TEXT","cipher_suite TEXT"]

#go to next line in the csv file
def read_next_csv_line():
    with open("suurls.csv", 'r', newline='', encoding='utf-8') as csv_file:
        reader = csv.reader(csv_file)
        next_line = next(reader, None)
        return next_line

    

# initialize driver
def begin_driver():
    driver = webdriver.Firefox()
    return driver

#close driver
def end_driver(driver):
    driver.quit()

#close current driver, open a new one
def new_driver(driver):
    end_driver(driver)
    new_driver = begin_driver()
    return new_driver

#close driver and GUI
def end_session(driver,window):
    if driver != None:
        end_driver(driver)
    window.destroy()

#next website in list
def next(driver,counter):
    driver = new_driver(driver)
    if counter < len(websites):
        driver.get(websites[counter])
    return driver



#look for indicators of SSO
def sso_check(driver,url,connection,cursor):
    result = enrollment.sso_check(driver)
    cursor.execute('UPDATE websites SET sso_check = ? WHERE url = ?', (str(result), url))
    connection.commit()
    print("Updated "+url+" to SSO: "+str(result))

#collect initial http information
def http_initial(driver):
    usage_unsafe_inline, use_of_wildcards, missing_object_src, safe_framing, \
        supports_hsts, supports_xframe, supports_xxss, supports_referrer_policy, supports_feature_policy = collectheader.main(driver)
    print("CSP Check--------------------------------------")
    print("Allows inline scripts without nonce:" + str(usage_unsafe_inline))
    print("At least one directive allows wildcards:" + str(use_of_wildcards))
    print("Lacks directives for object source:" + str(missing_object_src))
    print("Has safe framing policy in CSP:" + str(safe_framing))
    print("Other security headers--------------------------")
    print("Enforces HTTP Strict Transport Security:" + str(supports_hsts))
    print("x-frame-options exist and do not allow wildcard:" + str(supports_xframe))
    print("x-xss-protection exists:" + str(supports_xxss))
    print("Has strong referrer policy:" + str(supports_referrer_policy))
    print("feature-policy exists:" + str(supports_feature_policy))
    

#check if an email is immediately sent on account creation, from an address associated with the current website
def check_immediate_email(url):
    result = emailverification.immediate_feedback(url)
    print("Email from target source detected:" + str(result))

#check how the password is sent in the http request
def http_password_request(driver):
    message_found, request_type, sent_in_plaintext = http_passwordsubmission.scrape_requests(driver)
    
    print("--HTTP Password Submission--")
    print("Message Found: "+str(message_found))
    print("Sent in Plaintext: "+str(sent_in_plaintext))
    print("Request type: "+str(request_type))

#check the tls info and certificate
def get_tls_info(currentwebsite,url,cursor,connection):
    tls_version, cipher_suite = collecttls.get_tls_info(currentwebsite)
    print("TLS version:" + tls_version)
    cursor.execute('UPDATE websites SET tls_version = ? WHERE url = ?', (tls_version, url))
    cursor.execute('UPDATE websites SET cipher_suite = ? WHERE url = ?', (cipher_suite[0], url))
    connection.commit()
    print("Updated "+url+" to Cipher Suite: "+cipher_suite[0] )
    #cipher_suite[1] is tls/ssl protocol version
    #cipher_suite[2] is number of secret bits used for encryption
    print("Updated "+url+" to TLS Version: "+tls_version )


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


def main():
    #turn sign up url file into list
    websites = []
    with open("suurls.csv", 'r') as file:
        for line in file:
            websites.append(line.rstrip())


    #initialize driver
    driver = None
    
    #initialize db connection
    cwd = os.getcwd()
    connection = sqlite3.connect(cwd+"/db/test.db")
    cursor = connection.cursor()


    creation_string =("CREATE TABLE IF NOT EXISTS websites (url TEXT PRIMARY KEY")
    for entry in db_attributes:
        creation_string+=(", "+entry)
    creation_string+=");"
    cursor.execute(creation_string)
    connection.commit()
    
    #root window
    root = tk.Tk()
    root.geometry("850x550")
    
    #start frame---------------------------------------------------------------------------------------
    start = tk.Frame()
    startTitle = tk.Label(start,text="Start menu")
    startEnrollment = tk.Button(start,text="Start Enrollment",command=lambda : start_enrollment())
    currentwebsite = websites[0]
    currentWebsiteParsed = urlparse(currentwebsite).netloc.lower()
    start.pack()
    startTitle.pack()
    startEnrollment.pack()
    #start enrollment tests
    def start_enrollment():
        nonlocal driver
        driver = begin_driver()
        #enter first value
        driver.get(currentwebsite)
        create_db_row(currentWebsiteParsed,cursor,connection)


        start.pack_forget()
        enrollmentFrame.pack()
    #------------------------------------------------------------------------------------------------

    #enrollment frame -----------------------------------------------------------------------------
    enrollmentFrame = tk.Frame(root)
    enrollmentLabel = tk.Label(enrollmentFrame, text="Enrollment")
    endButtonStart = tk.Button(start,text="End Session",command=lambda : end_session(driver,root))
    enrollmentLabel.pack()
    endButtonStart.pack()

    websiteLabel = tk.Label(enrollmentFrame, text=currentWebsiteParsed)
    websiteLabel.pack()

    fillButton = tk.Button(enrollmentFrame,text="Fill",command=lambda : enrollment.autofill(driver))
    

    fillButton = tk.Button(enrollmentFrame,text="Fill",command=lambda : enrollment.autofill(driver))
    gettlsInfoButton = tk.Button(enrollmentFrame, text="Get TLS Info", command=lambda : get_tls_info(currentwebsite,currentWebsiteParsed,cursor,connection))
    initialHeaderButton = tk.Button(enrollmentFrame, text="Collect initial headers", command=lambda : http_initial(driver))
    checkImmediateEmailButton = tk.Button(enrollmentFrame, text="Check for email", command=lambda : check_immediate_email(currentwebsite))
    checkPasswordRequestButton = tk.Button(enrollmentFrame, text="Check HTTP requests for password submission", command=lambda : http_password_request(driver))
    endButton = tk.Button(enrollmentFrame,text="End Session",command=lambda : end_session(driver,root))

    c = 0
    
    def increment_and_next():
        nonlocal c
        nonlocal driver
        nonlocal currentwebsite
        nonlocal currentWebsiteParsed

        c = c+1
        if c < len(websites):
            currentwebsite = websites[c]
            currentWebsiteParsed = urlparse(currentwebsite).netloc.lower()
            websiteLabel.config(text = currentWebsiteParsed)
            create_db_row(currentWebsiteParsed,cursor,connection)
            driver = next(driver,c)
        
    nextButton = tk.Button(enrollmentFrame,text="Next site",command=lambda : increment_and_next())
    ssoButton = tk.Button(enrollmentFrame,text="Check SSO",command=lambda : sso_check(driver,currentWebsiteParsed,connection,cursor))
   
    
    nextButton.pack()
    fillButton.pack()
    ssoButton.pack()
    gettlsInfoButton.pack()
    initialHeaderButton.pack()
    checkImmediateEmailButton.pack()
    checkPasswordRequestButton.pack()
    endButton.pack()
    #-------------------------------------------------------------------------------------------------

    root.mainloop()

    #runs after GUI is closed
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



if __name__ == '__main__':
    main()