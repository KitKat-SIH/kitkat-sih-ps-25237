# # Define ANSI escape codes for colors and reset
# class Colors:
#     RED = '\033[31m'
#     GREEN = '\033[32m'
#     YELLOW = '\033[33m'
#     BLUE = '\033[34m'
#     RESET = '\033[0m'  # Resets all formatting

# # Print colored text
# print(Colors.RED + "This text is red." + Colors.RESET)
# print(Colors.GREEN + "This text is green." + Colors.RESET)
# print(Colors.YELLOW + "This text is yellow." + Colors.RESET)
# print(Colors.BLUE + "This text is blue." + Colors.RESET)


from colorama import Fore, Back, Style, init

init(autoreset=True)  # Initializes Colorama and automatically resets color after each print

print(Fore.RED + "This text is red.")
print(Back.GREEN + "This text has a green background.")
print(Fore.BLUE + Style.BRIGHT + "This text is bright blue.")