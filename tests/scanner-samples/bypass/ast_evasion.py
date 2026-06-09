#!/usr/bin/env python3
"""
BYPASS TEST 1: AST Evasion Techniques

Attempts to execute dangerous code while evading AST-based detection.
Each technique tries to hide exec/eval/subprocess from the AST visitor.
"""

# --- Technique 1: getattr to resolve exec dynamically ---
import builtins
fn = getattr(builtins, 'ex' + 'ec')
fn("import os; os.system('whoami')")

# --- Technique 2: String concatenation to build function name ---
danger = globals()['__builtins__']
evil_name = chr(101) + chr(118) + chr(97) + chr(108)  # "eval"
danger_fn = getattr(danger, evil_name)
danger_fn("print('pwned')")

# --- Technique 3: Using __class__ and __subclasses__ for code exec ---
empty = ''.__class__.__bases__[0].__subclasses__()
# Typically used to find os._wrap_close or similar

# --- Technique 4: importlib instead of __import__ ---
import importlib
mod = importlib.import_module("subprocess")
mod.run(["id"], capture_output=True)

# --- Technique 5: Decorator-based exec hiding ---
def runner(cmd):
    def wrapper(f):
        __builtins__.__dict__['exec'](cmd)
        return f
    return wrapper

@runner("import socket")
def innocent_looking():
    pass

# --- Technique 6: exec via compile + code object ---
code_str = "import os\nos.system('ls')"
code_obj = compile(code_str, '<string>', 'exec')
# Execute indirectly via function type
from types import FunctionType
FunctionType(code_obj, {})()

# --- Technique 7: Lambda chain to hide eval ---
e = lambda s: (lambda f: f(s))(eval)
e("__import__('os').system('id')")

# --- Technique 8: Class __init_subclass__ trick ---
class Backdoor:
    def __init_subclass__(cls, **kwargs):
        exec(kwargs.get('payload', ''))

class Trigger(Backdoor, payload="import os; os.system('whoami')"):
    pass
