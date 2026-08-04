# Check syntax of all YARA rules
cd /home/ubuntu/malware_sandbox/yara_rules

echo "=== Verifying YARA Rules ==="
for rule_file in yara_rules/*.yar; do
    echo "Checking: $rule_file"
    python3 -c "import yara; yara.compile('$rule_file')" 2>&1
    if [ $? -eq 0 ]; then
        echo "  ✓ Valid"
    else
        echo "  ✗ Invalid"
    fi
done

# Count total rules
echo -e "\n=== Rule Statistics ==="
for rule_file in yara_rules/*.yar; do
    rule_count=$(grep -c "^rule " "$rule_file")
    echo "$rule_file: $rule_count rules"
done
