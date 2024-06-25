import re

def validate_identifier(identifier):
    return re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", identifier) is not None

def validate_hex_string(hex_string):
    return re.match(r"^([0-9a-fA-F]{2}\s*)+$", hex_string) is not None

def validate_condition(condition):
    # Basic validation for logical expressions in conditions
    return re.match(r"^[a-zA-Z0-9\s\|\&\(\)\!\$]+$", condition) is not None

def get_input(prompt, validation_func, error_message):
    while True:
        value = input(prompt)
        if validation_func(value):
            return value
        else:
            print(error_message)

def get_meta():
    meta = {}
    while True:
        meta_key = input("Enter meta key (or press Enter to stop adding meta): ")
        if not meta_key:
            break
        meta_value = input(f"Enter value for meta key '{meta_key}': ")
        meta[meta_key] = meta_value
    return meta

def get_strings():
    strings = {}
    while True:
        string_id = get_input("Enter string identifier (or press Enter to stop adding strings): ", validate_identifier, "Invalid identifier. Must start with a letter or underscore and contain only alphanumeric characters and underscores.")
        if not string_id:
            break
        string_type = input("Enter type (text, hex, regex): ").strip().lower()
        if string_type == "text":
            string_value = input("Enter text string: ")
        elif string_type == "hex":
            string_value = get_input("Enter hex string: ", validate_hex_string, "Invalid hex string. Must contain pairs of hexadecimal digits separated by optional spaces.")
        elif string_type == "regex":
            string_value = input("Enter regex string: ")
        else:
            print("Unknown type. Please enter 'text', 'hex', or 'regex'.")
            continue
        strings[string_id] = {"type": string_type, "value": string_value}
    return strings

def main():
    print("Welcome to the YARA rule generator!")

    rule_name = get_input("Enter rule name: ", validate_identifier, "Invalid rule name. Must start with a letter or underscore and contain only alphanumeric characters and underscores.")

    tags = input("Enter tags (space-separated, optional): ")
    tags_list = tags.split() if tags else []

    print("\nNow, let's add some meta information. This section is optional but recommended.")
    meta = get_meta()

    print("\nNext, let's define the strings to be matched in the rule.")
    strings = get_strings()

    condition = get_input("Enter condition: ", validate_condition, "Invalid condition. Please enter a valid logical expression.")

    # Generate the YARA rule
    rule = f"rule {rule_name} {' '.join(tags_list)} {{\n"
    
    if meta:
        rule += "    meta:\n"
        for key, value in meta.items():
            rule += f"        {key} = \"{value}\"\n"
    
    if strings:
        rule += "    strings:\n"
        for sid, sval in strings.items():
            if sval["type"] == "text":
                rule += f"        ${sid} = \"{sval['value']}\"\n"
            elif sval["type"] == "hex":
                rule += f"        ${sid} = {{{sval['value']}}}\n"
            elif sval["type"] == "regex":
                rule += f"        ${sid} = /{sval['value']}/\n"
    
    rule += "    condition:\n"
    rule += f"        {condition}\n"
    rule += "}"
    
    print("\nGenerated YARA rule:\n")
    print(rule)

if __name__ == "__main__":
    main()
