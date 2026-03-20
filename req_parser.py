

import re
from typing import Dict
from pathlib import Path



def parse(file_path: str) -> Dict[str, str]:

    libraries = {}
    
    try:
        with open(file_path, 'r') as f:
            content = f.readlines()
    except FileNotFoundError:
        print(f"Файл {file_path} не найден")
        return {}
    
    patterns = [
        r'^\s*([a-zA-Z0-9_-]+)==([a-zA-Z0-9._+-]+)\s*',
        r'^\s*([a-zA-Z0-9_-]+)>=([a-zA-Z0-9._+-]+)\s*',
        r'^\s*([a-zA-Z0-9_-]+)<=([a-zA-Z0-9._+-]+)\s*',
        r'^\s*([a-zA-Z0-9_-]+)>([a-zA-Z0-9._+-]+)\s*',
        r'^\s*([a-zA-Z0-9_-]+)<([a-zA-Z0-9._+-]+)\s*',
        r'^\s*([a-zA-Z0-9_-]+)~=([a-zA-Z0-9._+-]+)\s*',
        r'^\s*([a-zA-Z0-9_-]+)\s*$',
        r'^\s*([a-zA-Z0-9_-]+)==([a-zA-Z0-9._+-]+)\s*#',
        r'^\s*([a-zA-Z0-9_-]+)\s*@\s*',
        r'^\s*([a-zA-Z0-9_-]+)\[.*?\]==([a-zA-Z0-9._+-]+)',
    ]
    
    for line in content:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        if line.startswith('-i ') or line.startswith('--index-url'):
            continue
        
        if line.startswith('--'):
            continue
        
        found = False
        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                lib_name = match.group(1).lower()
                version = match.group(2) if len(match.groups()) > 1 else None
                
                if '@' in line:
                    git_version_match = re.search(r'@.*?(v|version)?([0-9._+-]+)', line)
                    if git_version_match:
                        version = git_version_match.group(2)
                    else:
                        version = None
                
                libraries[lib_name] = version
                found = True
                break
        
        if not found:
            parts = re.split(r'[=<>~!@#]', line)
            if parts:
                lib_name = parts[0].strip().lower()
                if lib_name and not lib_name.startswith('-'):
                    libraries[lib_name] = None
                    print(f"Предупреждение: Нестандартный формат для '{line}', "
                          f"библиотека '{lib_name}' добавлена без версии")
    
    python_stdlib = {'os', 'sys', 'json', 're', 'datetime', 'pathlib', 
                    'typing', 'argparse', 'collections', 'itertools'}
    libraries = {k: v for k, v in libraries.items() if k not in python_stdlib}
    
    return libraries


def get_language() -> str:
    return "python"


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Использование: python requirements_parser.py <файл_requirements.txt>")
        sys.exit(1)
    
    result = parse(sys.argv[1])
    print(f"Найдено библиотек: {len(result)}")
    for lib, version in result.items():
        print(f"  {lib}: {version or 'без версии'}")