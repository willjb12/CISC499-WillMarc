from seleniumwire import webdriver
from seleniumwire.request import HTTPHeaders
from selenium.webdriver.common.by import By
import re



def parse_csp(csp_data):
    whitelists = []
    print(csp_data)
    usage_unsafe_inline = False
    use_of_wildcards = False
    missing_object_src = False
    
    script_src_pattern = re.compile(r'script-src\s+([^;]+)')
    object_src_pattern = re.compile(r'object-src\s+([^;]+)')
    base_uri_pattern = re.compile(r'base-uri\s+([^;]+)')
    default_src_pattern = re.compile(r'default-src\s+([^;]+)')
    frame_src_pattern = re.compile(r'frame-src\s+([^;]+)')
    style_src_pattern = re.compile(r'style-src\s+([^;]+)')
    img_src_pattern = re.compile(r'img-src\s+([^;]+)')
    font_src_pattern = re.compile(r'font-src\s+([^;]+)')
    connect_src_pattern = re.compile(r'connect-src\s+([^;]+)')
    media_src_pattern = re.compile(r'media-src\s+([^;]+)')
    form_action_pattern = re.compile(r'form-action\s+([^;]+)')
    frame_ancestors_pattern = re.compile(r'frame-ancestors\s([^;]+)')

    script_src_match = script_src_pattern.search(csp_data)
    object_src_match = object_src_pattern.search(csp_data)
    base_uri_match = base_uri_pattern.search(csp_data)
    default_src_match = default_src_pattern.search(csp_data)
    frame_src_match = frame_src_pattern.search(csp_data)
    style_src_match = style_src_pattern.search(csp_data)
    img_src_match = img_src_pattern.search(csp_data)
    font_src_match = font_src_pattern.search(csp_data)
    connect_src_match = connect_src_pattern.search(csp_data)
    media_src_match = media_src_pattern.search(csp_data)
    form_action_match = form_action_pattern.search(csp_data)
    frame_ancestors_match = frame_ancestors_pattern.search(csp_data)
    
    if script_src_match:
        script_src_values = script_src_match.group(1).split()
        whitelists.append(script_src_values)
        
        if "'unsafe-inline'" in script_src_values and "'nonce" not in ' '.join(script_src_values) and 'strict-dynamic' not in ' '.join(script_src_values):
            usage_unsafe_inline = True


    if not object_src_match and not default_src_match:
        missing_object_src = True
        
    else:
        missing_object_src = False
        
        if object_src_match:
            object_src_values = object_src_match.group(1).split()
            whitelists.append(object_src_values)
        if default_src_match:
            default_src_values = default_src_match.group(1).split()
            whitelists.append(default_src_values)
            
    
    if base_uri_match:
        base_uri_values = base_uri_match.group(1).split()
        whitelists.append(base_uri_values)
    if frame_src_match:
        frame_src_values = frame_src_match.group(1).split()
        whitelists.append(frame_src_values)
    if style_src_match:
        style_src_values = style_src_match.group(1).split()
        whitelists.append(style_src_values)
    if img_src_match:
        img_src_values = img_src_match.group(1).split()
        whitelists.append(img_src_values)
    if font_src_match:
        font_src_values = font_src_match.group(1).split()
        whitelists.append(font_src_values)
    if connect_src_match:
        connect_src_values = connect_src_match.group(1).split()
        whitelists.append(connect_src_values)
    if media_src_match:
        media_src_values = media_src_match.group(1).split()
        whitelists.append(media_src_values)
    if form_action_match:
        form_action_values = form_action_match.group(1).split()
        whitelists.append(form_action_values) 
    if frame_ancestors_match:
        frame_ancestors_values = frame_ancestors_match.group()

    for policy in whitelists:
        for entry in policy:
            if entry == "*":
                use_of_wildcards = True

    safe_framing = False
    if frame_ancestors_match:
        if '*' not in frame_ancestors_values:
            safe_framing = True
                          
    return usage_unsafe_inline, use_of_wildcards, missing_object_src, safe_framing 
        

def csp_search(driver):
    driver.implicitly_wait(5)
    csp_data = None
    other_headers = None
    meta_element = driver.find_element(By.XPATH, "//meta[contains(@http-equiv, 'Content-Security-Policy')]")

    
    for request in driver.requests:
        csp_data = request.response.headers.get("content-security-policy")
        if csp_data != None and \
           csp_data != "default-src 'none'; frame-ancestors 'none'; base-uri 'none';" and \
           csp_data != "default-src 'none'; style-src 'unsafe-inline'; sandbox":
            hsts_data = request.response.headers.get("strict-transport-security")
            xframe_data = request.response.headers.get("x-frame-options")
            xxss_data = request.response.headers.get("x-xss-protection")
            referrer_policy = request.response.headers.get("referrer-policy")
            feature_policy = request.response.headers.get("feature-policy")
            other_headers = [hsts_data, xframe_data, xxss_data, referrer_policy, feature_policy]
            break

    
    if csp_data == None:
        try:
            csp_data = meta_element.get_attribute("content")
        except:
            print("No CSP data found in HTML")

    
    return csp_data, other_headers
    
def scrape_header(first_request):
    first_response_head = first_request.response.headers
    csp_data = None
    hsts_data = None
    xframe_data = None
    xxss_data = None
    referrer_policy = None
    feature_policy = None
    
    
    csp_data = first_response_head.get("content-security-policy")
    
    hsts_data = first_response_head.get("strict-transport-security")
    
    xframe_data = first_response_head.get("x-frame-options")
    
    xxss_data = first_response_head.get("x-xss-protection")
    
    referrer_policy = first_response_head.get("referrer-policy")
    
    feature_policy = first_response_head.get("feature-policy")
    
    return csp_data, [hsts_data, xframe_data, xxss_data, referrer_policy, feature_policy]
    
def main(driver):
    first_request = driver.requests[0]
    
    csp_data, other_headers = scrape_header(first_request)
    
    csp_data_new = None
    if csp_data == None or \
       csp_data == "default-src 'none'; frame-ancestors 'none'; base-uri 'none';" or \
       csp_data == "default-src 'none'; style-src 'unsafe-inline'; sandbox":
        try:
            csp_data_new, other_headers_new = csp_search(driver)
        except:
            print("no csp data found or csp update failed")
        finally:
            if csp_data_new:
                csp_data = csp_data_new
                other_headers = other_headers_new

    
    if csp_data != None:
        usage_unsafe_inline, use_of_wildcards, missing_object_src, safe_framing = parse_csp(csp_data)
    else:
        usage_unsafe_inline, use_of_wildcards, missing_object_src, safe_framing = None, None, None, None

    if other_headers[0] != None:
        supports_hsts = True
    else:
        supports_hsts = False

    if other_headers[1] != None and "*" not in other_headers[1]:
        supports_xframe = True
    else:
        supports_xframe = False

    if other_headers[2] != None:
        supports_xxss = True
    else:
        supports_xxss = False
        
    supports_referrer_policy = False
    for s in ["no-referrer", "strict-origin-when-cross-origin", "same-origin", "origin"]:    
        if other_headers[3] != None and s in other_headers[3]:
            supports_referrer_policy = True
            

    if other_headers[4] != None:
        supports_feature_policy = True
    else:
        supports_feature_policy = False

    

    
    return usage_unsafe_inline, use_of_wildcards, missing_object_src, safe_framing, \
            supports_hsts, supports_xframe, supports_xxss, supports_referrer_policy, supports_feature_policy  

