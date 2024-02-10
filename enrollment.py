from selenium import webdriver
from selenium.webdriver.common.by import By
import time
import tkinter as tk

secrets = []
with open("secret.txt", 'r') as file:
    lines = file.readlines()
    for line in lines:
        secrets.append(line.rstrip())

email=secrets[0]
username="test_username"
password=secrets[1]


#AUTOFILL HELPER FUNCTIONS--------------------------------------------------------------------

#search for username input fields
def find_username_input(driver):
        username_fields = []
        attributes = ["*","name","id","aria-label","type"]
        for a in attributes:
            try:
                username_fields += driver.find_elements(By.XPATH,"//input[contains(translate(@"+a+", 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'USERNAME')]")
            except:
                None
            try:
                username_fields += driver.find_elements(By.XPATH,"//*[contains(translate(@"+a+", 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'USERNAME')]")
            except:
                None
        return username_fields

#search for password input fields
def find_password_input(driver):
    try:
        password_fields = driver.find_elements(By.XPATH,'//input[@type="password"]')
        return password_fields
    except:
        return []

#search for email input fields
def find_email_input(driver):
    email_fields = []
    attributes = ["*","name","id","aria-label","autocomplete"]
    for a in attributes:
        try:
            email_fields += driver.find_elements(By.XPATH,"//input[contains(translate(@"+a+", 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'EMAIL')]")
        except:
            None
        try:
            email_fields += driver.find_elements(By.XPATH,"//*[contains(translate(@"+a+", 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'EMAIL')]")
        except:
            None
    return email_fields


#--------------------------------------------------------------------------

# auto fill function
def autofill(driver):
    username_inputs = find_username_input(driver)
    username_inputs = list(dict.fromkeys(username_inputs))
    password_inputs = find_password_input(driver)
    password_inputs = list(dict.fromkeys(password_inputs))
    email_inputs = find_email_input(driver)
    email_inputs = list(dict.fromkeys(email_inputs))
    
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
        for u in username_inputs:
            try:
                u.clear()
                u.send_keys(username)
            except:
                None

# check for sso options
def sso_check(driver):
    found_sso_elems = []
    attributes = ["*","id","aria-label","autocomplete","title"]
    sso_ind_str = ["LOG IN WITH", "SIGN IN WITH", "CONTINUE WITH", "SIGN UP WITH"]
    sso_ind_array = [["SIGN","WITH"],["CONTINUE","WITH"],["LOG","WITH"],["CONT","WITH"]]
    
    #check for sso in attributes
    for a in attributes:
        try:
            found_sso_elems += driver.find_elements(By.XPATH,"//button[contains(translate(@"+a+", 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'SSO')]")
        except Exception as e:
                None
        try:
            found_sso_elems += driver.find_elements(By.XPATH,"//*[contains(translate(@"+a+", 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'SSO')]")  
        except Exception as e:
                None
        try:
            found_sso_elems += driver.find_elements(By.XPATH,"//iframe[contains(translate(@"+a+", 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'SSO')]")  
        except Exception as e:
                None
        
        #check for multi-word indicators in attributes
        for i in sso_ind_array:
            first = i[0]
            second = i[1]
            try:
                found_sso_elems += driver.find_elements(By.XPATH, "//button[contains(translate(@"+a+", 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), '" + first + "') and contains(translate(@" + a + ", 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), '" + second + "')]")
            except Exception as e:
                None
            try:
                found_sso_elems += driver.find_elements(By.XPATH,"//iframe[contains(translate(@"+a+", 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), '" + first + "') and contains(translate(@" + a + ", 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), '" + second + "')]")
            except Exception as e:
                None
            try:
                found_sso_elems += driver.find_elements(By.XPATH,"//*[contains(translate(@"+a+", 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), '" + first + "') and contains(translate(@" + a + ", 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), '" + second + "')]")
            except Exception as e:
                None

    #check in text for keywords
    for j in sso_ind_str:
        try:
            found_sso_elems += driver.find_elements(By.XPATH,"//*[contains(translate(text(), 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'"+j+"')]")
        except Exception as e:
                None
    
    if len(found_sso_elems)>0:
        for element in found_sso_elems:
            if element.is_displayed():
                return True
        return False
    else:
        return False
