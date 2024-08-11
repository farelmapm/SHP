'''
    Secure Header Protocol

    This Stuff is created to make Richard's Life easier. Static analysis is fun, but staring at header is not.

    What To Do:
    V 1. Define the Logging (green, blue, yellow, red)
    V 2. Parsing the Header 
    V 3. Cookie
    V 4. HSTS
    V 5. CSP
    V 6. Rating of PASS - WARNING - FAIL
    7. 
    
    To Add in the future:
    1. auto request -> parse ke txt -> txtnya di check (to do, later, sometime in the future)
'''

# Logging and Stuff
GREEN = "\033[92m"
BLUE = "\033[94m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def risk(a,b,c,headerToCheck):
    # a - pass, b - warning, c - error, headerToCheck - Header Name
    if a / (a+b+c) == 1:
        return (f'{headerToCheck} {GREEN}SECURE{RESET}')
    elif a / (a+b+c) >= 0.65:
        return (f'{headerToCheck} {YELLOW}WARNING{RESET}')
    else:
        return (f'{headerToCheck} {RED}FAILED{RESET}')    

def success(message):
    print(f"\t[{GREEN}✓{RESET}] {message}")

def success_with_xtratab(message):
    print(f"\t\t[{GREEN}✓{RESET}] {message}")

def info(message):
    print(f"\t[{BLUE}*{RESET}] {message}")

def info_with_xtratab(message):
    print(f"\t\t[{BLUE}*{RESET}] {message}")

def warning(message):
    print(f"\t[{YELLOW}!{RESET}] {message}")

def warning_with_xtratab(message):
    print(f"\t\t[{YELLOW}!{RESET}] {message}")

def error(message):
    print(f"\t[{RED}x{RESET}] {message}")

def error_with_xtratab(message):
    print(f"\t\t[{RED}x{RESET}] {message}")

# Adding the Parser
def parse_headers_and_body(data):
    headers = {} # Define that headers is Dictionary
    body = ""
    
    # Split the data into header lines and body
    header_part, _, body_part = data.partition("\n\n")
    
    # Process headers
    lines = header_part.splitlines()
    for line in lines:
        if not line or not ":" in line:
            continue
        
        key, value = line.split(": ", 1)
        if key in headers:
            headers[key].append(value)
        else:
            headers[key] = [value]
    
    # Process body (if any)
    body = body_part.strip()
    
    return headers, body

# Opening the file
def read_file(file_path):
    """Read the contents of a text file and return them."""
    try:
        with open(file_path, 'r') as file:
            content = file.read()
        return content
    except FileNotFoundError:
        return error("File not found.")
    except Exception as e:
        return error(f"An error occurred: {e}")

# Cookie Checker
def setcookieChecker(data):
    # Set-Cookie
    aCounter = 0
    bCounter = 0
    cCounter = 0
    print('Set-Cookie')
    # Define how many cookies present in the data
    countCookie = len(data['Set-Cookie'])
    
    #Condition for Many Cookies and only single cookie
    if(countCookie == 1):
        x = data['Set-Cookie'][0]
        cookieName = x.split('=')[0]
        print(cookieName)
        secureAttribute = {
            'HttpOnly' : 'HttpOnly' in x,
            'Secure'   : 'Secure' in x,
            'Strict'   : 'Strict' in x,
            'Lax'   : 'Lax' in x,
            'None'   : 'None' in x,
            'Max-Age' : next((part.split('=', 1)[1] for part in x.split('; ') if part.startswith('Max-Age=')), False),
            'expires' : 'expires' in x
        }
        if (secureAttribute['expires'] == False and secureAttribute['Max-Age'] == True):
            if(value == 'Max-Age' and int(secureAttribute[value]) <= 86400): # under 1 day
                success_with_xtratab(f'Set-Cookie for {cookieName} has a Max-Age of under 86400 (1 day), with the value of {secureAttribute[value]}')
                aCounter+=1
            elif(value == 'Max-Age' and int(secureAttribute[value]) >= 86400): # greater than 1 day
                warning_with_xtratab(f'Set-Cookie for {cookieName} has a Max-Age greater than 86400 (1 day)')
                bCounter+=1
        # cari tau max value for expire
        elif (secureAttribute['expires'] == True and secureAttribute['Max-Age'] == False):
            success_with_xtratab(f'Set-Cookie for {cookieName} has expires attribute.')
            aCounter+=1
        elif (secureAttribute['expires'] == False and secureAttribute['Max-Age'] == False):
            error_with_xtratab(f'Set-Cookie for {cookieName} has no expires or max-age attribute!')
            cCounter+=1
        for value in secureAttribute:
            if (value == 'expires' or value == 'Max-Age'):
                continue
            if(value == 'Strict' or value == 'Lax' or value == 'None' and secureAttribute[value] == False):
                continue
            elif(value == 'Strict' or value == 'Lax' and secureAttribute[value] == True):
                success_with_xtratab(f'Set-Cookie for {cookieName} has SameSite={value} attribute.')
                aCounter+=1
            elif(value == 'None' and secureAttribute['Secure'] == False):
                warning_with_xtratab(f'Set-Cookie for {cookieName} is using SameSite={value} but missing Secure attribute!')
                bCounter+=1
            if(secureAttribute[value] == True):
                success_with_xtratab(f'Set-Cookie for {cookieName} has {value} attribute.')
                aCounter+=1
            if(secureAttribute[value] == False):
                error_with_xtratab(f'Set-Cookie for {cookieName} is missing {value} attribute.')
                cCounter+=1
    elif(countCookie > 1):
        for x in data['Set-Cookie']:
            cookieName = x.split('=')[0]
            print('\t' + cookieName)
            secureAttribute = {
                'HttpOnly' : 'HttpOnly' in x,
                'Secure'   : 'Secure' in x,
                'Strict'   : 'Strict' in x,
                'Lax'   : 'Lax' in x,
                'None'   : 'None' in x,
                'Max-Age' : next((part.split('=', 1)[1] for part in x.split('; ') if part.startswith('Max-Age=')), False),
                'expires' : 'expires' in x
            }

            if (secureAttribute['expires'] == False and secureAttribute['Max-Age'] == True):
                if(value == 'Max-Age' and int(secureAttribute[value]) <= 86400): # under 1 day
                    success_with_xtratab(f'Set-Cookie for {cookieName} has a Max-Age of under 86400 (1 day), with the value of {secureAttribute[value]}')
                    aCounter+=1
                    continue
                elif(value == 'Max-Age' and int(secureAttribute[value]) >= 86400): # greater than 1 day
                    warning_with_xtratab(f'Set-Cookie for {cookieName} has a Max-Age greater than 86400 (1 day)')
                    bCounter+=1
                    continue
            # cari tau max value for expire - No Answer :') ywd wkwk
            elif (secureAttribute['expires'] == True and secureAttribute['Max-Age'] == False):
                success_with_xtratab(f'Set-Cookie for {cookieName} has expires attribute.')
                aCounter+=1
                continue
            elif (secureAttribute['expires'] == False and secureAttribute['Max-Age'] == False):
                error_with_xtratab(f'Set-Cookie for {cookieName} has no expires or max-age attribute!')
                cCounter+=1
            for value in secureAttribute:
                if (value == 'expires' or value == 'Max-Age'):
                    continue
                if(value == 'Strict' or value == 'Lax' or value == 'None' and secureAttribute[value] == False):
                    continue
                elif(value == 'Strict' or value == 'Lax' and secureAttribute[value] == True):
                    success_with_xtratab(f'Set-Cookie for {cookieName} has SameSite={value} attribute.')
                    aCounter+=1
                elif(value == 'None' and secureAttribute['Secure'] == False):
                    warning_with_xtratab(f'Set-Cookie for {cookieName} is using SameSite={value} but missing Secure attribute!')
                    bCounter+=1
                if(secureAttribute[value] == True):
                    success_with_xtratab(f'Set-Cookie for {cookieName} has {value} attribute.')
                    aCounter+=1
                if(secureAttribute[value] == False):
                    error_with_xtratab(f'Set-Cookie for {cookieName} is missing {value} attribute.')
                    cCounter+=1
    result =  risk(aCounter,bCounter,cCounter,'Set-Cookie')
    return result

# HSTS Checker            
def hstsChecker(data):
    aCounter = 0
    bCounter = 0
    cCounter = 0
    headerName = 'Strict-Transport-Security'
    print(headerName)
    x = data[headerName][0] #adding 0 to index the first data since it's only one string
    secureAttribute = {
        'max-age' : next((part.split('=', 1)[1] for part in x.split('; ') if part.startswith('max-age=')), None),
        'includeSubDomains' : 'includeSubDomains' in x,
        'preload' : 'preload' in x
    }
    for value in secureAttribute:
        if(value == 'max-age' and int(secureAttribute[value]) >= 31536000):
            success(f'HSTS for {value} is already following standard of at least 1 year (31536000), used {secureAttribute[value]}')
            aCounter+=1
        elif(value == 'max-age' and int(secureAttribute[value]) < 31536000):
            warning(f'HSTS for {value} is not following the standard of at least 1 year, used {secureAttribute[value]}')
            bCounter+=1
        if(secureAttribute[value] == True):
            success(f'HSTS for {value} is set on the Header.')
            aCounter+=1
        if(secureAttribute[value] == False):
            error(f'HSTS of {value} is missing!')
            cCounter+=1
    result = risk(aCounter,bCounter,cCounter,'Strict-Transport-Security')
    return result

# CSP Checker
def cspChecker(data):
    aCounter=0
    bCounter=0
    cCounter=0
    print('Content-Security-Policy')
    x = data['Content-Security-Policy'][0].split(';')
    # Valid CSP Directive Reference
    cspValidReference = [
        'default-src', 'script-src', 'style-src', 'img-src', 
        'connect-src', 'font-src', 'media-src', 'object-src', 
        'frame-src', 'sandbox', 'report-uri', 'child-src', 
        'form-action', 'frame-ancestors', 'plugin-types', 'base-uri', 
        'report-to', 'worker-src', 'prefetch-src', 'manifest-src', 
        'navigate-to', 'upgrade-insecure-requests', 
        'block-all-mixed-content' 
    ]
    # Create a Dictionary to List available 
    cspSources = {}
    for sources in x:
        sources = sources.strip()
        if sources:
            # Find the separator between the key and the value
            parts = sources.split(' ', 1)
            key = parts[0]
            # Check if Key is a valid CSP Directive Reference
            if(key in cspValidReference):
                value = parts[1] if len(parts) > 1 else ''
                cspSources[key] = value
    # Begin Check for Every
    for key in cspSources:
        print(f'\t{key}')
        # print(f'\n{cspSources[key]}')
        # print(cspSources[key])
        # List Reference
        cspList = {
            '*' : any(part == '*' for part in cspSources[key].split()),
            '*.' : '*.' in cspSources[key],
            'none' : 'none' in cspSources[key],
            'self' : 'self' in cspSources[key],
            'https:' : 'https:' in cspSources[key],
            'http:' : 'http:' in cspSources[key],
            'unsafe-inline' : 'unsafe-inline' in cspSources[key],
            'unsafe-eval' : 'unsafe-eval' in cspSources[key],
            'sha256-' : 'sha256-' in cspSources[key],
            'nonce-' : 'nonce-' in cspSources[key],
            'strict-dynamic' : 'strict-dynamic' in cspSources[key],
            'unsafe-hashes' : 'unsafe-hashes' in cspSources[key],
            'data:' : 'data:' in cspSources[key],
            'blob:' : 'blob:' in cspSources[key],
            'script' : 'script' in cspSources[key]
        }
        if cspList['none'] and all(value == False for key, value in cspList.items() if key != 'none'):
            success_with_xtratab(f'CSP only has none, it\'s secure.')
            aCounter+=1
            continue
        if cspList['nonce-'] == True:
            success_with_xtratab(f'CSP has the secure attribute of nonce-')
            aCounter+=1
            if cspList['sha256-'] == True:
                success_with_xtratab(f'CSP has the secure attribute of sha256-')
                aCounter+=1
                continue
        sdExist = False
        if(cspList['strict-dynamic'] == True):
            sdExist=True
            aCounter+=1
        blob_check = cspList['blob:']
        data_check = cspList['data:']
        # print(data_check,blob_check)
        https_check = cspList.get('https:', False)
        http_check = cspList.get('http:', False)
        wildcard_check = cspList.get('*', False)
        star_check = cspList.get('*.', False)
        # all required attribute
        combineData = [data_check, blob_check, sdExist]
        dataString = ['data:', 'blob:', 'strict-dynamic']
        combineProto = [https_check, http_check, star_check]
        protoString = ['https:', 'http:', '*.']
        all_exist = False
        all_exist_counter = 0
        to_print_for_proto = 'making the '
        to_print_for_data = 'use '
        # Check what type of Protocol exist
        for i,exist in enumerate(combineProto):
            if exist and i != len(combineProto) - 1:
                to_print_for_proto += '\'' + protoString[i] + '\', '
            elif exist and i == len(combineProto) - 1:
                to_print_for_proto += '\'' + protoString[i] + '\''
            elif i == len(combineProto) - 1 and len(to_print_for_proto) == 11:
                to_print_for_proto = 'and has no resourse to fetch'
        # print(to_print_for_proto, len(to_print_for_proto))
        if to_print_for_proto != '' and to_print_for_proto[-2] == ',' :
            to_print_for_proto = to_print_for_proto[:-2] 
        # print(to_print_for_proto, to_print_for_proto[-2])
        # Check what Type of Assignment
        for i, exist in enumerate(combineData):
            if exist and i != len(combineData) - 1:
                to_print_for_data += f'{dataString[i]} '
            elif exist and i == len(combineData) - 1:
                to_print_for_data += f'and has \'{dataString[i]}\''
            elif i == len(combineData) - 1 and exist == False:
                # print('this is start>>', to_print_for_data, len(to_print_for_data))
                if len(to_print_for_data) == 4:
                    to_print_for_data = f'not using \'data:\' \'blob:\' and missing \'{dataString[i]}\''
                    continue
                to_print_for_data += f'but missing \'{dataString[i]}\''
        # print(to_print_for_data)
        # SD WD ga peduli
        # SD FALSE - WD EXIST
        # SD FALSE - WD FALSE
        if(len(to_print_for_proto) != 28):
            if(sdExist == False and wildcard_check == False):
                final_string = f'CSP {to_print_for_data}, {to_print_for_proto} in danger. Make sure to only allow resources download over HTTPS'
                warning_with_xtratab(final_string)
                bCounter+=1
            elif(sdExist and wildcard_check == True or wildcard_check == False):
                final_string = f'CSP {to_print_for_data} {to_print_for_proto} Secure.'
                success_with_xtratab(final_string)
                aCounter+=1
            elif(sdExist == False and wildcard_check):
                final_string = f'CSP {to_print_for_data} and \'*\' exist, {to_print_for_proto} Unsafe.'
                error_with_xtratab(final_string)
                cCounter+=1
            if(key == 'form-action' and cspList['self'] == False):
                error_with_xtratab(f'CSP of form-action need at least \'self\' attribute to be secure!')
                cCounter+=1
            elif(key == 'form-action' and cspList['self'] == True):
                success_with_xtratab(f'CSP of form-action has the minimum attribute of \'self\'.')
                aCounter+=1
        elif(len(to_print_for_proto) == 28):
            if(sdExist == False and wildcard_check == False):
                final_string = f'CSP {to_print_for_data}, {to_print_for_proto}.'
                warning_with_xtratab(final_string)
                bCounter+=1
            elif(sdExist and wildcard_check == True or wildcard_check == False):
                final_string = f'CSP {to_print_for_data} {to_print_for_proto}.'
                success_with_xtratab(final_string)
                aCounter+=1
            elif(sdExist == False and wildcard_check):
                final_string = f'CSP {to_print_for_data} and \'*\' exist, {to_print_for_proto}.'
                error_with_xtratab(final_string)
                cCounter+=1
            if(key == 'form-action' and cspList['self'] == False):
                error_with_xtratab(f'CSP of form-action need at least \'self\' attribute to be secure!')
                cCounter+=1
            elif(key == 'form-action' and cspList['self'] == True):
                success_with_xtratab(f'CSP of form-action has the minimum attribute of \'self\'.')
                aCounter+=1
        noNeedToCheckAgain = ['http:', 'https:', 'none', 'nonce-', 'sha256', 'data:', '*.', '*','blob:', 'strict-dynamic', 'self']
        for value in cspList:
            # form-action has a special condition
            if(key != 'form-action' and value == 'self'):
                warning_with_xtratab(f'CSP is using a \'self\' and could be dangerous if the using host JSONP, AngularJS or user upload-file')
            if(cspList[value] == True and value not in noNeedToCheckAgain):
                error_with_xtratab(f'CSP is using a possibly unsafe method of \'{value}\'')
                cCounter+=1
    result = risk(aCounter,bCounter,cCounter,'Content-Security-Policy')
    # print(aCounter,bCounter,cCounter)
    return result

# Opening Response

response_content = read_file("./ToCheck/response.txt")
parsed_data, body = parse_headers_and_body(response_content)

# Checking for functionality
result_setCookie = setcookieChecker(parsed_data)
result_HSTS = hstsChecker(parsed_data)
result_CSP =  cspChecker(parsed_data)

print(
'''
========================================================
|                       RESULT                         |
========================================================
'''
)
print(result_setCookie)
print(result_HSTS)
print(result_CSP)


# print(body)