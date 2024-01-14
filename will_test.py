from selenium import webdriver
from selenium.webdriver.common.by import By
import time

#sign-up page indicators
sign_in_indicators = ["SIGNIN","SIGNUP","LOGIN"]
sign_up_indicators = [["SIGN","UP"],["CREATE","ACCOUNT"],["START","HERE"],["SIGN","IN"]]
email_indicator = []
username_indicator = []
password_indicator = []

#start firefox
driver = webdriver.Firefox()
driver.get("https://www.bestbuy.ca")

#wait for load
time.sleep(3)

loginpage = False

#find signup page

#check for log in fields
if loginpage == True:
    text_entry_boxes = driver.find_elements(By.XPATH,'//input[@type="text"]')
    passwords = driver.find_elements(By.XPATH,'//input[@type="password"]')



if loginpage==False:
    
#looking for button to create account
    for jeremy in sign_up_indicators:
        a = jeremy[0]
        b = jeremy[1]
        button1 = driver.find_elements(By.XPATH,"//*[contains(translate(text(), 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'), '"+a+"') and contains(translate(text(), 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'),'"+b+"')]")
        for button in button1:
            try:
                button.click()
            except:
                print("error on button")
    


if loginpage ==False:
#look for links to bring you to sign-in indicated pages
    link_buttons = driver.find_elements(By.XPATH,"//a[@href]")
    if (len(link_buttons)>0):
        for elem in link_buttons:
            for i in sign_in_indicators:
             if (i in elem.get_attribute("href").upper()):
                 elem.click()
    
time.sleep(3)

                    