import json
file_path = 'password.json'

# Read and load the JSON file
with open(file_path, 'r') as file:
    data = json.load(file)

print(data)

