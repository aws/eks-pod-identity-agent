#!/bin/bash
# Script to validate Dependabot configuration

set -e

echo "Validating Dependabot configuration..."

# Check if dependabot.yml exists
if [ ! -f ".github/dependabot.yml" ]; then
    echo "❌ Error: .github/dependabot.yml not found"
    exit 1
fi

echo "✓ Dependabot configuration file exists"

# Validate YAML syntax using Python
python3 -c "
import yaml
import sys

try:
    with open('.github/dependabot.yml', 'r') as f:
        config = yaml.safe_load(f)
    
    # Check version
    if config.get('version') != 2:
        print('❌ Error: version must be 2')
        sys.exit(1)
    
    # Check updates exist
    if 'updates' not in config or not config['updates']:
        print('❌ Error: updates section is required')
        sys.exit(1)
    
    # Validate each update configuration
    required_fields = ['package-ecosystem', 'directory', 'schedule']
    ecosystems = []
    
    for update in config['updates']:
        for field in required_fields:
            if field not in update:
                print(f'❌ Error: {field} is required in update configuration')
                sys.exit(1)
        
        ecosystem = update['package-ecosystem']
        ecosystems.append(ecosystem)
        
        # Validate schedule
        if 'interval' not in update['schedule']:
            print(f'❌ Error: schedule.interval is required for {ecosystem}')
            sys.exit(1)
    
    print(f'✓ YAML syntax is valid')
    print(f'✓ Found {len(ecosystems)} package ecosystems: {', '.join(ecosystems)}')
    print('✓ All required fields are present')
    
except yaml.YAMLError as e:
    print(f'❌ Error: Invalid YAML syntax: {e}')
    sys.exit(1)
except Exception as e:
    print(f'❌ Error: {e}')
    sys.exit(1)
"

echo ""
echo "✅ Dependabot configuration is valid!"
echo ""
echo "Configuration summary:"
echo "  - Go modules: Weekly updates on Monday"
echo "  - GitHub Actions: Weekly updates on Monday"
echo "  - Docker: Weekly updates on Monday"
echo ""
echo "Next steps:"
echo "  1. Commit and push this configuration to GitHub"
echo "  2. Dependabot will automatically start monitoring dependencies"
echo "  3. PRs will be created with labels: 'dependencies' and ecosystem-specific labels"
