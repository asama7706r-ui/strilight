# stop_dict.py
# قاموس التوقف للدوال - Stop dictionary for functions

# قائمة بالدوال التي يجب أن يتوقف المحرك عندها أو يتخطاها (API Boundaries)
STOP_FUNCTIONS = {
    # دوال الإدخال والقراءة (تتطلب تفاعل أو انتظار)
    "scanf": "input",
    "gets": "input",
    "fgets": "input",
    "read": "input",
    "ReadFile": "input",
    "recv": "network_input",
    
    # دوال الكتابة والإخراج (لا نحتاج لتتبع تفاصيلها الداخلية)
    "printf": "output",
    "puts": "output",
    "fputs": "output",
    "write": "output",
    "WriteFile": "output",
    "send": "network_output"
}
