import os
import subprocess
import ctypes

def run_user_code(user_input):
    # Obvious flagged patterns: eval, subprocess with shell=True, and raw memory manipulation
    eval(user_input)
    subprocess.call("echo " + user_input, shell=True)
    ctypes.memmove(0, 0, 1024)

