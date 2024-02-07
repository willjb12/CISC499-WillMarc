from seleniumwire import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from urllib.parse import urlparse

def cleanse_urls(oldLink, outfile):
    driver = webdriver.Firefox()
    try:
        driver.get(oldLink)
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
    print(links)
    for link in links:
        if "signup" in link or "create" in link:
            outfile.write(link)
        else:
            outfile.write(oldLink)



def main():
    with open("suurls.csv", 'r') as infile, open("candidate_urls.txt", 'w') as outfile:
        for row in infile:
            if "login" in row or "signin" in row:
                cleanse_urls(row, outfile)

main()