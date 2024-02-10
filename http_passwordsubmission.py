from seleniumwire import webdriver
 
def scrape_requests(driver):
    secrets = []
    with open("secret.txt", 'r') as file:
        lines = file.readlines()
        for line in lines:
            secrets.append(line.rstrip())

    email = secrets[0]
    password = secrets[1]
    requests = driver.requests
    websites = []
   

    post_pass = None
    get_pass = None
    possible_post_request = []
    possible_get_request = []
    
    for request in requests:
        if request.method == "POST" and b"password" in request.body \
           and (b"name" in request.body or b"email" in request.body):
            possible_post_request.append(request)
            
        elif request.method == "POST" and b"pw" in request.body \
           and (b"name" in request.body or b"email" in request.body):
            possible_post_request.append(request)

        elif request.method == "GET" and "password" in request.url \
             and ("name" in request.url or "email" in request.url):
            possible_get_request.append(request)
            
        elif request.method == "GET" and "pw" in request.url \
             and ("name" in request.url or "email" in request.url):
            possible_get_request.append(request)

        elif request.method == "POST" and \
            (bytes(password, 'utf-8') in request.body or bytes(email.split('@')[0], 'utf-8')):
            possible_post_request.append(request)

        elif request.method == "GET" and \
             (password in request.url or email.split('@')[0] in request.url):
            possible_get_request.append(request)


    for request in possible_post_request:
        if bytes(password, 'utf-8') in request.body or bytes(email.split('@')[0], 'utf-8') in request.body:
            post_pass = request
            message_found = True

            #print(request.url)
            #print("password in plain:" + str(bytes(password, 'utf-8') in request.body))
            #print("username in plain:" + str(bytes(email.split('@')[0], 'utf-8') in request.body))

            if bytes(password, 'utf-8') in request.body:
                sent_in_plaintext = True
                break
            else:
                sent_in_plaintext = False

    for request in possible_get_request:
        if password in request.url or email in request.url:
            get_pass = request
            message_found = True

            if password in request.url:
                sent_in_plaintext = True
                break
            else:
                sent_in_plaintext = False


    if post_pass == None and get_pass == None:
        request_type = "Not Found"
    elif post_pass != None:
        request_type = "POST"
    elif get_pass != None:
        request_type = "GET"
    else:
        request_type = "Both"

    
    print("Post Message:")
    if post_pass:
        print(f"Keywords found in POST Request URL: {post_pass.url}")
        print(f"POST Request Headers: {post_pass.headers}")
        print(f"POST Request Body: {post_pass.body}")
    print("Get Message:")
    if get_pass:
        print(f"Keywords found in GET Request URL: {get_pass.url}")
        print(f"GET Request Headers: {get_pass.headers}")
    

    return message_found, request_type, sent_in_plaintext
    


    

    

