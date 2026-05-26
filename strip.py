import re
import sys

def main():
    try:
        with open('event_mapper.py', 'r', encoding='utf-8') as f:
            code = f.read()

        # Remove "Tactic": "...",
        code = re.sub(r'[ \t]*"Tactic"\s*:\s*".*?",\n', '', code)
        # Remove "Technique_Name": "...",
        code = re.sub(r'[ \t]*"Technique_Name"\s*:\s*".*?",\n', '', code)

        with open('event_mapper.py', 'w', encoding='utf-8') as f:
            f.write(code)
        print('Successfully stripped dicts.')
    except Exception as e:
        print('Error:', e)
        sys.exit(1)

if __name__ == '__main__':
    main()
