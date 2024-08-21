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
import argparse
from Utils import CustomLogger as log 
from Utils import RiskCalculator as rc

banner = """
Secure Header Protocol: \n
\nHeader Checker for Request and Response via txt file.
"""

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
        return log.error("File not found.")
    except Exception as e:
        return log.error(f"An error occurred: {e}")

# OWASP Proposed Value
def OWASPproposed(data):
    print()
    aCounter = 0
    bCounter = 0
    cCounter = 0
    print(
"""
========================================================
|         Check if OWASP Proposed Header Exist         |
========================================================
"""
    )
    secureHeaders = {
        "Strict-Transport-Security": ["max-age=31536000", "includeSubDomains"],
        "X-Frame-Options": ["deny"],
        "Content-Security-Policy": [
            "default-src 'self'", 
            "form-action 'self'", 
            "object-src 'none'", 
            "frame-ancestors 'none'", 
            "upgrade-insecure-requests", 
            "block-all-mixed-content"
        ],
        "X-Permitted-Cross-Domain-Policies": ["none"],
        "Referrer-Policy": ["no-referrer"],
        "Clear-Site-Data": ["cache", "cookies", "storage"],
        "Cross-Origin-Embedder-Policy": ["require-corp"],
        "Cross-Origin-Opener-Policy": ["same-origin"],
        "Cross-Origin-Resource-Policy": ["same-origin"],
        "Permissions-Policy": [
            "accelerometer", "autoplay", "camera", "cross-origin-isolated", 
            "display-capture", "encrypted-media", "fullscreen", "geolocation", 
            "gyroscope", "keyboard-map", "magnetometer", "microphone", "midi", 
            "payment", "picture-in-picture", "public-credentials-get", "screen-wake-lock", 
            "sync-xhr", "usb", "web-share", "xr-spatial-tracking", 
            "clipboard-read", "clipboard-write", "gamepad", "hid", 
            "idle-detection", "interest-cohort", "serial", "unload"
        ],
        "Cache-Control": ["no-store", "max-age=0"]
    }
    for headers in data:
        original_key = next((key for key in secureHeaders if key.lower() == headers), None)
        if headers.lower() in (key.lower() for key in secureHeaders):
            print(original_key)
            if original_key != None and len(secureHeaders[original_key]) > 1:
                # print(len(secureHeaders[original_key]), headers)
                for value in secureHeaders[original_key]:
                    if any(value in headersValue for headersValue in data[headers]):
                        log.success_with_xtratab(f'{value} exist on {original_key}')
                        aCounter+=1
                    else:
                        log.warning_with_xtratab(f'{value} is missing on {original_key}')
                        bCounter+=1
            elif original_key != None and len(secureHeaders[original_key]) == 1:
                if value in data[headers]:
                    log.success_with_xtratab(f'{value} exist on {original_key}')
                    aCounter+=1
                else:
                    log.warning_with_xtratab(f'{value} is missing on {original_key}')
                    bCounter+=1
        else:
            if original_key != None and len(secureHeaders[original_key]) > 1:
                # print(len(secureHeaders[original_key]), headers)
                for value in secureHeaders[original_key]:
                    if any(value in headersValue for headersValue in data[headers]):
                        log.success_with_xtratab(f'{value} exist on {original_key}')
                        aCounter+=1
                    else:
                        log.warning_with_xtratab(f'{value} is missing on {original_key}')
                        bCounter+=1
            elif original_key != None and len(secureHeaders[original_key]) == 1:
                if value in data[headers]:
                    log.success_with_xtratab(f'{value} exist on {original_key}')
                    aCounter+=1
                else:
                    log.warning_with_xtratab(f'{value} is missing on {original_key}')
                    bCounter+=1
    if (aCounter / (aCounter + bCounter)) >= 0.8:
        print(f"The Response Headers follows OWASP Secure Header Proposal {log.bigSuccess()}")
    elif (aCounter / (aCounter + bCounter)) < 0.8 and (aCounter / (aCounter + bCounter)) >= 0.5:
        print(f'The Response Headers Implement some of OWASP Secure Header Proposal {log.bigWarning()}')
    elif (aCounter / (aCounter + bCounter)) < 0.5:
        print(f'The Respone Headers is likely to be Customized or just Insecure {log.bigWarning()}')
# Cookie Checker
def setcookieChecker(data):
    # Set-Cookie
    aCounter = 0
    bCounter = 0
    cCounter = 0
    print('Set-Cookie')
    # Define how many cookies present in the data
    countCookie = 0
    if "Set-Cookie" in data:
        countCookie = len(data['Set-Cookie'])
    else:
        log.info_with_xtratab("No Cookie was found in the response")
        return rc.not_found("Set-Cookie")

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
                log.success_with_xtratab(f'Set-Cookie for {cookieName} has a Max-Age of under 86400 (1 day), with the value of {secureAttribute[value]}')
                aCounter+=1
            elif(value == 'Max-Age' and int(secureAttribute[value]) >= 86400): # greater than 1 day
                log.warning_with_xtratab(f'Set-Cookie for {cookieName} has a Max-Age greater than 86400 (1 day)')
                bCounter+=1
        # cari tau max value for expire
        elif (secureAttribute['expires'] == True and secureAttribute['Max-Age'] == False):
            log.success_with_xtratab(f'Set-Cookie for {cookieName} has expires attribute.')
            aCounter+=1
        elif (secureAttribute['expires'] == False and secureAttribute['Max-Age'] == False):
            log.error_with_xtratab(f'Set-Cookie for {cookieName} has no expires or max-age attribute!')
            cCounter+=1
        for value in secureAttribute:
            if (value == 'expires' or value == 'Max-Age'):
                continue
            if(value == 'Strict' or value == 'Lax' or value == 'None' and secureAttribute[value] == False):
                continue
            elif(value == 'Strict' or value == 'Lax' and secureAttribute[value] == True):
                log.success_with_xtratab(f'Set-Cookie for {cookieName} has SameSite={value} attribute.')
                aCounter+=1
            elif(value == 'None' and secureAttribute['Secure'] == False):
                log.warning_with_xtratab(f'Set-Cookie for {cookieName} is using SameSite={value} but missing Secure attribute!')
                bCounter+=1
            if(secureAttribute[value] == True):
                log.success_with_xtratab(f'Set-Cookie for {cookieName} has {value} attribute.')
                aCounter+=1
            if(secureAttribute[value] == False):
                log.error_with_xtratab(f'Set-Cookie for {cookieName} is missing {value} attribute.')
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
                    log.success_with_xtratab(f'Set-Cookie for {cookieName} has a Max-Age of under 86400 (1 day), with the value of {secureAttribute[value]}')
                    aCounter+=1
                    continue
                elif(value == 'Max-Age' and int(secureAttribute[value]) >= 86400): # greater than 1 day
                    log.warning_with_xtratab(f'Set-Cookie for {cookieName} has a Max-Age greater than 86400 (1 day)')
                    bCounter+=1
                    continue
            # cari tau max value for expire - No Answer :') ywd wkwk
            elif (secureAttribute['expires'] == True and secureAttribute['Max-Age'] == False):
                log.success_with_xtratab(f'Set-Cookie for {cookieName} has expires attribute.')
                aCounter+=1
                continue
            elif (secureAttribute['expires'] == False and secureAttribute['Max-Age'] == False):
                log.error_with_xtratab(f'Set-Cookie for {cookieName} has no expires or max-age attribute!')
                cCounter+=1
            for value in secureAttribute:
                if (value == 'expires' or value == 'Max-Age'):
                    continue
                if(value == 'Strict' or value == 'Lax' or value == 'None' and secureAttribute[value] == False):
                    continue
                elif(value == 'Strict' or value == 'Lax' and secureAttribute[value] == True):
                    log.success_with_xtratab(f'Set-Cookie for {cookieName} has SameSite={value} attribute.')
                    aCounter+=1
                elif(value == 'None' and secureAttribute['Secure'] == False):
                    log.warning_with_xtratab(f'Set-Cookie for {cookieName} is using SameSite={value} but missing Secure attribute!')
                    bCounter+=1
                if(secureAttribute[value] == True):
                    log.success_with_xtratab(f'Set-Cookie for {cookieName} has {value} attribute.')
                    aCounter+=1
                if(secureAttribute[value] == False):
                    log.error_with_xtratab(f'Set-Cookie for {cookieName} is missing {value} attribute.')
                    cCounter+=1
    result =  rc.risk(aCounter,bCounter,cCounter,'Set-Cookie')
    return result

# HSTS Checker            
def hstsChecker(data):
    aCounter = 0
    bCounter = 0
    cCounter = 0
    headerName = 'Strict-Transport-Security'
    print(headerName)
    if headerName in data:
        headerName = headerName
    else:
        headerName = headerName.lower()
        print(headerName)
    x = data[headerName][0] #adding 0 to index the first data since it's only one string
    secureAttribute = {
        'max-age' : next((part.split('=', 1)[1] for part in x.split('; ') if part.startswith('max-age=')), None),
        'includeSubdomains' : 'includeSubdomains' in x,
        'preload' : 'preload' in x
    }
    for value in secureAttribute:
        if(value == 'max-age' and int(secureAttribute[value]) >= 31536000):
            log.success(f'HSTS for {value} is already following standard of at least 1 year (31536000), used {secureAttribute[value]}')
            aCounter+=1
        elif(value == 'max-age' and int(secureAttribute[value]) < 31536000):
            log.warning(f'HSTS for {value} is not following the standard of at least 1 year, used {secureAttribute[value]}')
            bCounter+=1
        if(secureAttribute[value] == True):
            log.success(f'HSTS for {value} is set on the Header.')
            aCounter+=1
        if(secureAttribute[value] == False):
            log.error(f'HSTS of {value} is missing!')
            cCounter+=1
    result = rc.risk(aCounter,bCounter,cCounter,'Strict-Transport-Security')
    return result

# CSP Checker
def cspChecker(data):
    aCounter=0
    bCounter=0
    cCounter=0
    headerName = 'Content-Security-Policy'
    print('Content-Security-Policy')
    if headerName in data:
        headerName = headerName
    else:
        headerName = headerName.lower()
    x = data[headerName][0].split(';')
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
            log.success_with_xtratab(f'CSP only has none, it\'s secure.')
            aCounter+=1
            continue
        if cspList['nonce-'] == True:
            log.success_with_xtratab(f'CSP has the secure attribute of nonce-')
            aCounter+=1
            if cspList['sha256-'] == True:
                log.success_with_xtratab(f'CSP has the secure attribute of sha256-')
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
                log.warning_with_xtratab(final_string)
                bCounter+=1
            elif(sdExist and wildcard_check == True or wildcard_check == False):
                final_string = f'CSP {to_print_for_data} {to_print_for_proto} Secure.'
                log.success_with_xtratab(final_string)
                aCounter+=1
            elif(sdExist == False and wildcard_check):
                final_string = f'CSP {to_print_for_data} and \'*\' exist, {to_print_for_proto} Unsafe.'
                log.error_with_xtratab(final_string)
                cCounter+=1
            if(key == 'form-action' and cspList['self'] == False):
                log.error_with_xtratab(f'CSP of form-action need at least \'self\' attribute to be secure!')
                cCounter+=1
            elif(key == 'form-action' and cspList['self'] == True):
                log.success_with_xtratab(f'CSP of form-action has the minimum attribute of \'self\'.')
                aCounter+=1
        elif(len(to_print_for_proto) == 28):
            if(sdExist == False and wildcard_check == False):
                final_string = f'CSP {to_print_for_data}, {to_print_for_proto}.'
                log.warning_with_xtratab(final_string)
                bCounter+=1
            elif(sdExist and wildcard_check == True or wildcard_check == False):
                final_string = f'CSP {to_print_for_data} {to_print_for_proto}.'
                log.success_with_xtratab(final_string)
                aCounter+=1
            elif(sdExist == False and wildcard_check):
                final_string = f'CSP {to_print_for_data} and \'*\' exist, {to_print_for_proto}.'
                log.error_with_xtratab(final_string)
                cCounter+=1
            if(key == 'form-action' and cspList['self'] == False):
                log.error_with_xtratab(f'CSP of form-action need at least \'self\' attribute to be secure!')
                cCounter+=1
            elif(key == 'form-action' and cspList['self'] == True):
                log.success_with_xtratab(f'CSP of form-action has the minimum attribute of \'self\'.')
                aCounter+=1
        noNeedToCheckAgain = ['http:', 'https:', 'none', 'nonce-', 'sha256', 'data:', '*.', '*','blob:', 'strict-dynamic', 'self']
        for value in cspList:
            # form-action has a special condition
            if(key != 'form-action' and value == 'self'):
                log.warning_with_xtratab(f'CSP is using a \'self\' and could be dangerous if the using host JSONP, AngularJS or user upload-file')
            if(cspList[value] == True and value not in noNeedToCheckAgain):
                log.error_with_xtratab(f'CSP is using a possibly unsafe method of \'{value}\'')
                cCounter+=1
    result = rc.risk(aCounter,bCounter,cCounter,'Content-Security-Policy')
    # print(aCounter,bCounter,cCounter)
    return result

# Information Header 
def infoHeaderChecker(data):
    print(
"""
========================================================
|     Checking for Information Leakage Possibility     |
========================================================
"""
    )
    information_headers = {
        'X-Powered-By',
        'Server',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
        'X-Drupal-Cache',
        'X-Jenkins',
        'X-Joomla-Token',
        "X-Magento-Vary"
        "X-Pingback",
        "X-Generator",
        "X-Runtime",
        "Via",
        "X-Cache",
        "X-Backend-Server",
        "Content-Location",
        "Public-Key-Pins"
    }

    found = {}
    for headers in data:
        if headers in information_headers or headers in (key.lower() for key in information_headers):
            found[headers] = True
    
    if len(found) > 0:
        print(f"Information Header(s) was found! {log.bigWarning()} {log.bigError()}\n")
        for headers in found:
            log.warning(f'{headers} was found in the response. Information disclosure is possible')
    else:
        print(f"No Information Header(s) was found. {log.bigSuccess()}\n" )
    print("")

# Caching Header
def cachingHeaderChecker(data):
    print(
"""
========================================================
|          Checking for Cache Control Headers          |
========================================================
"""
)
    cacheHeaders = {
        "Expires",
        "Pragma",
        "Vary",
        "Etag",
        "Last-Modified",
        "Age",
        "Warning",
        "Cache-Control"
    }
    found = {}
    for headers in data:
        if headers in cacheHeaders or headers in (key.lower() for key in cacheHeaders):
            found[headers] = True
    
    if len(found) > 0:
        print(f"Cache Control Header(s) was found! {log.bigWarning()} {log.bigError()}\n")
        for headers in found:
            log.warning(f'{headers} was found in the response.')
    else:
        print(f"No Cache Header(s) was found. {log.bigWarning()} {log.bigSuccess()}\n" )
    print("")

# Security Header Check
def SecureResponseHeaderCheck(data):
    print(
"""
========================================================
|             Checking for Secure Headers              |
========================================================
"""
    )
    result_setCookie = setcookieChecker(data)
    result_HSTS = hstsChecker(data)
    result_CSP =  cspChecker(data)

    print(
"""
========================================================
|                       RESULT                         |
========================================================
"""
    )
    print(result_setCookie)
    print(result_HSTS)
    print(result_CSP)

def main():
    # add Parser Obejct to enable --help
    # add description to tools
    parser = argparse.ArgumentParser(description=f"{banner}")

    # Add the --file argument
    parser.add_argument("--file", required=True, help="Path to the response file")

    # Parse the arguments
    args = parser.parse_args()

    # Call the SecureHeaderCheck function with the file argument
    response_content = read_file(args.file)
    parsed_data, body = parse_headers_and_body(response_content)

    # # # First Check for Information Headers
    infoHeaderChecker(parsed_data)
    # # Second Check for Cache Control headers
    cachingHeaderChecker(parsed_data)
    # # Third Check for OWASP SHP
    OWASPproposed(parsed_data)
    # # Fourth Check for the Secure Header if they exist
    SecureResponseHeaderCheck(parsed_data)

if __name__ == "__main__":
    main()