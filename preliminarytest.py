from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.firefox.options import Options
from urllib.parse import urlparse
import csv
import os

def lookforsu(domain):
    driver = webdriver.Firefox()
        
    cur = "http://www." + domain

    try:
        driver.get(cur)
    except Exception as e:
        driver.quit()
        print(f"an exception has occured, the site did not connect: {e}")
        return False, None
    
    driver.implicitly_wait(5)

    try:
        hits = driver.find_elements(By.XPATH, "//a[@href]")
    except Exception as e:
        driver.quit()
        print(f"an exception has occured, while finding nodes: {e}")
        return False, None

    links=[]
    for elem in hits:
        try:
            links.append(elem.get_attribute("href").lower())
        except Exception as e:
            print(f"an exception has occured, the href attribute was not found: {e}")

    sulink=''
    for url in links:
        if "signin" in url:
            sulink = url
        elif "signup" in url:
            sulink = url
        elif "login" in url:
            sulink = url
    
    driver.quit()

    if sulink != '':
        return True, sulink

    return False, cur


def writetocsv(url, location):
    with open(location, 'a', newline='') as file:
        write = csv.writer(file, quoting=csv.QUOTE_NONE, escapechar='\\')
        write.writerow([url])
    
def main():
    with open("top-1m.csv", newline='') as file:
        lineread = csv.reader(file, delimiter = ',')
        ct = 0
        rows = 500
        for row in lineread:
            if ct < rows:
                print(row[1])
                found, url = lookforsu(row[1])
                if found:
                    writetocsv(url, "suurls.csv")
                else:
                    if url != None:
                        writetocsv(url, "tentativeurls.csv")
                ct += 1
            else:
                break


if __name__ == '__main__':
    main()
