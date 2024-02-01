from selenium import webdriver
from selenium.webdriver.common.by import By
import time
import tkinter as tk
import sqlite3
import os
import enrollment

websites = ["https://reddit.com","https://facebook.com","https://amazon.ca"]
db_attributes = ["sso_check TEXT"]

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
        enrollment.pack()
    #------------------------------------------------------------------------------------------------

    #enrollment frame -----------------------------------------------------------------------------
    enrollment = tk.Frame(root)
    enrollmentLabel = tk.Label(enrollment, text="Enrollment")
    enrollmentLabel.pack()
    currentwebsite = websites[0]
    websiteLabel = tk.Label(enrollment, text=currentwebsite)
    websiteLabel.pack()
    fillButton = tk.Button(enrollment,text="Fill",command=lambda : enrollment.autofill(driver))
    endButton = tk.Button(enrollment,text="End Session",command=lambda : end_session(driver,root))
    c = 0
    
    def increment_and_next(driver):
        nonlocal c
        nonlocal currentwebsite
        c = c+1
        if c < len(websites):
            currentwebsite = websites[c]
        websiteLabel.config(text = currentwebsite)
        next(driver,c)
    nextButton = tk.Button(enrollment,text="Next site",command=lambda : increment_and_next(driver))
    ssoButton = tk.Button(enrollment,text="Check SSO",command=lambda : sso_check(driver))
   
    
    nextButton.pack()
    fillButton.pack()
    ssoButton.pack()
    endButton.pack()
    #-------------------------------------------------------------------------------------------------

    root.mainloop()
    print("over")



if __name__ == '__main__':
    main()