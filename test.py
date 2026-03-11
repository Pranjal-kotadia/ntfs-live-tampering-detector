import json

with open('results.json') as f:
    data = json.load(f)

# Put the names of files YOU tampered with here
my_files = ['backdoor.exe', 'mimikatz.dll', 'pivot.ps1']

print('YOUR TAMPERED FILES:')
print('-'*50)
found = 0

for f in data['findings']:
    if any(name in f['file_path'] for name in my_files):
        print(f"[{f['severity']}] {f['confidence_score']}% - {f['file_path']}")
        for d in f['details']:
            print(f"  -> {d}")
        print()
        found += 1

print(f"Found {found} of your tampered files")
