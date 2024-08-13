# color codes (ANSI escape sequences)
GREEN = '\033[92m'
BLUE = '\033[94m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'

# Log Status
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

def bigSuccess():
    return (f'{GREEN}SECURE{RESET}')

def bigWarning():
    return (f'{YELLOW}WARNING{RESET}')

def bigError():
    return (f'{RED}FAILED{RESET}')  