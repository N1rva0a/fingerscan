# List to store the fingerprints
fingerprints = []

# Function to add new fingerprints
def add_fingerprint(name, rules):
    fingerprints.append({
        'name': name,
        'rules': rules
    })

# Example rule sets for specific CMS

def phpcms_rules():
    return [
        lambda normalized_body, title, x_powered_by, user_agent: "http://www.phpcms.cn" in normalized_body,
        lambda normalized_body, title, x_powered_by, user_agent: 'content="phpcms"' in normalized_body,
        lambda normalized_body, title, x_powered_by, user_agent: 'phpcms' in normalized_body,
        lambda normalized_body, title, x_powered_by, user_agent: "powered by phpcms" in normalized_body,
        lambda normalized_body, title, x_powered_by, user_agent: "data/config.js" in normalized_body,
        lambda normalized_body, title, x_powered_by, user_agent: "/index.php?m=content&c=index&a=lists" in normalized_body,
        lambda normalized_body, title, x_powered_by, user_agent: "phpcms(盛大)" in title,
        lambda normalized_body, title, x_powered_by, user_agent: "http://www.phpcms.cn" in normalized_body and "powered by" in normalized_body,
        lambda normalized_body, title, x_powered_by, user_agent: '<a href="http://www.phpcms.cn" target="_blank">phpcms</a>' in normalized_body
    ]

# Example rule sets for another CMS, e.g., 
# def rules():
#     return [
#         lambda normalized_body, title, x_powered_by, user_agent: "" in normalized_body,
#     ]


# Example: Add default fingerprints
add_fingerprint('PhpCMS', phpcms_rules())