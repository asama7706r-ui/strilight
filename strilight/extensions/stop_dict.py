# stop_dict.py
# Stop dictionary for functions

# List of functions where the engine should stop or skip (API Boundaries)
STOP_FUNCTIONS = {
    # Input and reading functions (require interaction or waiting)
    "scanf": "input",
    "gets": "input",
    "fgets": "input",
    "read": "input",
    "ReadFile": "input",
    "recv": "network_input",
    "atoi": "input_conversion",
    "atol": "input_conversion",
    "strtol": "input_conversion",
    "sscanf": "input_conversion",
    "_atoi64": "input_conversion",
    
    # Writing and output functions (we don't need to track their internal details)
    "printf": "output",
    "puts": "output",
    "fputs": "output",
    "write": "output",
    "WriteFile": "output",
    "send": "network_output"
}
