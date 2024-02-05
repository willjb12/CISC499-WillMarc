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

websites = ["https://pinterest.com","https://www.instagram.com/","https://reddit.com","https://facebook.com","https://amazon.ca","https://twitter.com","https://wikipedia.org","https://yahoo.com","https://tiktok.com"]



db_attributes = ["sso_check TEXT"]

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



#look for indicators of SSO
def sso_check(driver):
    result = enrollment.sso_check(driver)
    print(result)

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

#check the tls info and certificate
def get_tls_info(currentwebsite):
    tls_version, cipher_suite = collecttls.get_tls_info(currentwebsite)
    print("TLS version:" + tls_version)
    #print("Cipher suite:" + cipher_suite) 


#next website in list
def next(driver,counter):
    if counter < len(websites):
        driver.get(websites[counter])

#close driver and GUI
def end_session(driver,window):
    end_driver(driver)
    window.destroy()

#close current driver, open a new one
def new_driver(driver):
    end_driver(driver)
    new_driver = begin_driver()
    return new_driver

def main():
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

    start.pack()
    startTitle.pack()
    startEnrollment.pack()
    def start_enrollment():
        nonlocal driver
        driver = begin_driver()
        driver.get(websites[0])
        start.pack_forget()
        enrollmentFrame.pack()
    #------------------------------------------------------------------------------------------------

    #enrollment frame -----------------------------------------------------------------------------
    enrollmentFrame = tk.Frame(root)
    enrollmentLabel = tk.Label(enrollmentFrame, text="Enrollment")
    enrollmentLabel.pack()
    currentwebsite = websites[0]
    websiteLabel = tk.Label(enrollmentFrame, text=currentwebsite)
    websiteLabel.pack()

    fillButton = tk.Button(enrollmentFrame,text="Fill",command=lambda : enrollment.autofill(driver))
    endButton = tk.Button(enrollmentFrame,text="End Session",command=lambda : end_session(driver,root))

    fillButton = tk.Button(enrollmentFrame,text="Fill",command=lambda : enrollment.autofill(driver))
    gettlsInfoButton = tk.Button(enrollmentFrame, text="Get TLS Info", command=lambda : get_tls_info(currentwebsite))
    initialHeaderButton = tk.Button(enrollmentFrame, text="Collect initial headers", command=lambda : http_initial(driver))
    checkImmediateEmailButton = tk.Button(enrollmentFrame, text="Check for email", command=lambda : check_immediate_email(currentwebsite))
    checkPasswordRequestButton = tk.Button(enrollmentFrame, text="Check HTTP requests for password submission", command=lambda : http_password_request(driver))
    endButton = tk.Button(enrollmentFrame,text="End Session",command=lambda : end_session(driver,root))

    c = 0
    
    def increment_and_next(driver):
        nonlocal c
        nonlocal currentwebsite
        c = c+1
        if c < len(websites):
            currentwebsite = websites[c]
        websiteLabel.config(text = currentwebsite)
        next(driver,c)
    nextButton = tk.Button(enrollmentFrame,text="Next site",command=lambda : increment_and_next(driver))
    ssoButton = tk.Button(enrollmentFrame,text="Check SSO",command=lambda : sso_check(driver))
   
    
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
    print("over")



if __name__ == '__main__':
    main()