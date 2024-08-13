# color codes (ANSI escape sequences)
GREEN = '\033[92m'
BLUE = '\033[94m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'

def risk(a,b,c,headerToCheck):
    # a - pass, b - warning, c - error, headerToCheck - Header Name
    if a / (a+b+c) == 1:
        return (f'{headerToCheck} {GREEN}SECURE{RESET}')
    elif a / (a+b+c) >= 0.65:
        return (f'{headerToCheck} {YELLOW}WARNING{RESET}')
    else:
        return (f'{headerToCheck} {RED}FAILED{RESET}')   