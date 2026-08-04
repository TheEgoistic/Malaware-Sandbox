import yara
import os

def scan_with_yara(file_path, rules_dir):
    """Compile YARA rules from a directory and scan the file."""
    matches = []
    if not os.path.isdir(rules_dir):
        print(f"YARA rules directory not found: {rules_dir}")
        return matches

    # Compile all .yar files in the directory
    rules = {}
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(".yar"):
                rule_path = os.path.join(root, file)
                try:
                    rules[file] = rule_path
                except Exception as e:
                    print(f"Error loading rule file {file}: {e}")

    if not rules:
        return matches

    try:
        compiled_rules = yara.compile(filepaths=rules)
        scan_matches = compiled_rules.match(file_path, timeout=60) # 60-second timeout
        for match in scan_matches:
            matches.append({
                "rule": match.rule,
                "tags": match.tags,
                "strings": [str(s) for s in match.strings]
            })
    except yara.TimeoutError:
        matches.append({"error": "YARA scan timed out."})
    except yara.Error as e:
        matches.append({"error": f"YARA error: {e}"})

    return matches
