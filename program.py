from selenium import webdriver
from selenium.webdriver.common.by import By
import time
import tkinter as tk
import sqlite3
import os

email="example@example.com"
username="exampleguy"
password="secret"
websites = ["https://reddit.com","https://facebook.com","https://amazon.ca"]
db_attributes = ["[sso_check] TEXT"]

# initialize driver
def begin():
    driver = webdriver.Firefox()
    return driver

def end(driver,window):
    driver.quit()
    window.destroy()

def next(driver,counter):
    if counter < len(websites):
        driver.get(websites[counter])

#--------------------------------------------------------------------

#search for username input fields
def find_username_input(driver):

    try:
        username_fields = driver.find_elements(By.XPATH,"//input[contains(translate(@*, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'USERNAME')]")
        if len(username_fields)>0:
            return username_fields
        else:
            try:
                username_fields = driver.find_elements(By.XPATH,"//input[contains(translate(@name, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'USERNAME')]")
                return username_fields
            except:
                None
    except:
        None
    return []

#search for password input fields
def find_password_input(driver):
    password_indicators = [['PASSWORD']]
    try:
        password_fields = driver.find_elements(By.XPATH,'//input[@type="password"]')
        return password_fields
    except:
        return []

#search for email input fields
def find_email_input(driver):
    email_indicators = [['EMAIL']]
    try:
        email_fields = driver.find_elements(By.XPATH,"//input[contains(translate(@*, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'EMAIL')]")
        if len(email_fields)>0:
            return email_fields
        else:
            try:
                email_fields = driver.find_elements(By.XPATH,"//input[contains(translate(@aria-label, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'EMAIL')]")
                return email_fields
            except:
                None
    except:
        None
    return []


#--------------------------------------------------------------------------

# auto fill function
def autofill(driver):
    username_inputs = find_username_input(driver)
    password_inputs = find_password_input(driver)
    email_inputs = find_email_input(driver)
    
    if email_inputs != None:
        for e in email_inputs:
            try:
                e.clear()
                e.send_keys(email)
            except:
                None
    if password_inputs != None:
        for p in password_inputs:
            try:
                p.clear()
                p.send_keys(password)
            except:
                None
    if username_inputs != None:
        print(len(username_inputs))
        for u in username_inputs:
            try:
                u.clear()
                u.send_keys(u)
            except:
                None

#look for indicators of SSO
def sso_check(driver):
    sso_indicators = [["SIGN","WITH"],["CONTINUE","WITH"]]
    for indicators in sso_indicators:
        a = indicators[0]
        b = indicators[1]
        sso_elems =  driver.find_elements(By.XPATH,"//*[contains(translate(text(), 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), '"+a+"') and contains(translate(text(), 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'"+b+"')]")
        if (len(sso_elems) >= 1):
            for b in sso_elems:
                try:
                    b.click()
                    print("SSO True")
                    return True
                except:
                    None
    print("SSO False")
    return False



def main():
    #initialize drivre
    driver = None
    #initialize db connection
    cwd = os.getcwd()
    connection = sqlite3.connect(cwd+"/db/test.db")
    cursor = connection.cursor()
    creation_string =("CREATE TABLE IF NOT EXISTS websites ([website_URL] TEXT PRIAMRY KEY")
    for entry in db_attributes:
        creation_string+=(", "+entry)
    creation_string+=")"
    print(creation_string)
    cursor.execute(creation_string)
    connection.commit()

    print(connection.total_changes)

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
        driver = begin()
        driver.get(websites[0])
        start.pack_forget()
        enrollment.pack()
    #------------------------------------------------------------------------------------------------

    #enrollment frame -----------------------------------------------------------------------------
    enrollment = tk.Frame(root)
    enrollmentLabel = tk.Label(enrollment, text="Enrollment")
    fillButton = tk.Button(enrollment,text="Fill",command=lambda : autofill(driver))
    endButton = tk.Button(enrollment,text="End Session",command=lambda : end(driver,root))
    c = 0
    def increment_and_next(driver):
        nonlocal c
        c = c+1
        next(driver,c)
    nextButton = tk.Button(enrollment,text="Next site",command=lambda : increment_and_next(driver))
    ssoButton = tk.Button(enrollment,text="Check SSO",command=lambda : sso_check(driver))
   
    enrollmentLabel.pack()
    nextButton.pack()
    fillButton.pack()
    ssoButton.pack()
    endButton.pack()
    #-------------------------------------------------------------------------------------------------

    root.mainloop()
    print("over")



if __name__ == '__main__':
    main()