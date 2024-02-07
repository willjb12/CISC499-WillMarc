import imaplib
import email
from email.header import decode_header
from urllib.parse import urlparse
import dkim

def from_dkim(bytemail):
     try:
         dkim_domain = dkim.verify(bytemail).lower()
     except dkim.VerifyError:
         return None

     return dkim_domain

def from_expected(domain, bytemail):
    message = email.message_from_bytes(bytemail)
    sender = message.get("From")

    possible_domain = sender.replace("@", ".").split(".")
    expected = domain.split('.')[1]
    
    if expected in sender:
        return True
    elif expected in from_dkim(bytemail):
        return True

    return False

    
def get_last_mail(imap_ssl):
    imap_ssl.select()

    result, mail_ids = imap_ssl.uid("search", None, 'ALL')

    prev = mail_ids[0].split()[-1]

    result, data = imap_ssl.uid("fetch", prev, '(RFC822)')

    bytemail = data[0][1]

    return bytemail

def immediate_feedback(url):
    try:
        imap_ssl = imaplib.IMAP4_SSL(host="imap.gmail.com", port=993)
    except Exception as e:
        print(f"an exception has ocurred, imap object not created: {e}")
        imap_ssl = None

    try:
        resp_code, response = imap_ssl.login()
    except Exception as e:
        print(f"an exception has ocurred, login failed: {e}")
        resp_code, response = None, None

    bytemail = get_last_mail(imap_ssl)

    domain = urlparse(url).netloc.lower()

    verified = from_expected(domain, bytemail)
    
    imap_ssl.logout()
    

