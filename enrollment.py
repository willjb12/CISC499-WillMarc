from selenium import webdriver
from selenium.webdriver.common.by import By
import time
import tkinter as tk


email="example@example.com"
username="exampleguy"
password="secret"


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
    sso_indicators = [["SIGN","WITH"],["CONTINUE","WITH"],["LOG","WITH"]]
    for indicators in sso_indicators:
        a = indicators[0]
        b = indicators[1]
        sso_elems =  driver.find_elements(By.XPATH,"//*[contains(translate(text(), 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), '"+a+"') and contains(translate(text(), 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'"+b+"')]")
        if (len(sso_elems) >= 1):
            for b in sso_elems:
                try:
                    b.click()
           
                    return True
                except:
                    None
    
    return False