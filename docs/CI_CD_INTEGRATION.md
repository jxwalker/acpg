# CI/CD Integration Guide

## Overview

ACPG can be integrated into CI/CD pipelines to automatically check code compliance before merging or deploying. This guide provides examples for common CI/CD platforms.

---

## GitHub Actions

### Basic Integration

```yaml
name: Compliance Check

on:
  pull_request:
    branches: [ main, develop ]
  push:
    branches: [ main ]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install ACPG
        run: |
          pip install -r requirements.txt
      
      - name: Start ACPG Services
        run: |
          cd /path/to/acpg
          ./scripts/start.sh
      
      - name: Wait for ACPG
        run: |
          until curl -f http://localhost:6000/api/v1/health; do
            sleep 2
          done
      
      - name: Run Compliance Check
        run: |
          for file in $(find . -name "*.py" -not -path "./venv/*"); do
            code=$(cat "$file")
            response=$(curl -s -X POST http://localhost:6000/api/v1/enforce \
              -H "Content-Type: application/json" \
              -d "{\"code\": $(echo "$code" | jq -Rs .), \"language\": \"python\"}")
            
            compliant=$(echo "$response" | jq -r '.compliant')
            if [ "$compliant" != "true" ]; then
              echo "❌ $file is not compliant"
              echo "$response" | jq '.violations'
              exit 1
            fi
          done
      
      - name: Generate Proof Bundle
        if: success()
        run: |
          # Generate proof bundle for the entire codebase
          curl -X POST http://localhost:6000/api/v1/proof/generate \
            -H "Content-Type: application/json" \
            -d @- <<EOF
          {
            "code": "$(cat $(find . -name "*.py" | head -1))",
            "language": "python"
          }
          EOF
```

### Advanced Integration with Proof Bundles

```yaml
name: Compliance Check with Proofs

on:
  pull_request:
    branches: [ main ]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      
      - name: Install Dependencies
        run: |
          pip install requests
      
      - name: Start ACPG
        run: |
          cd /path/to/acpg
          ./scripts/start.sh
      
      - name: Check Compliance
        id: compliance
        run: |
          python3 << 'EOF'
          import requests
          import json
          import os
          
          base_url = "http://localhost:6000/api/v1"
          
          # Find all Python files
          python_files = []
          for root, dirs, files in os.walk('.'):
              if 'venv' in root or '.git' in root:
                  continue
              for file in files:
                  if file.endswith('.py'):
                      python_files.append(os.path.join(root, file))
          
          all_compliant = True
          proofs = []
          
          for file_path in python_files:
              with open(file_path, 'r') as f:
                  code = f.read()
              
              # Analyze
              r = requests.post(f"{base_url}/analyze", json={
                  "code": code,
                  "language": "python"
              })
              analysis = r.json()
              
              # Adjudicate
              r = requests.post(f"{base_url}/adjudicate", json=analysis)
              adjudication = r.json()
              
              if not adjudication['compliant']:
                  print(f"❌ {file_path} is not compliant")
                  all_compliant = False
              
              # Generate proof
              r = requests.post(f"{base_url}/proof/generate", json={
                  "code": code,
                  "analysis": analysis,
                  "adjudication": adjudication,
                  "language": "python"
              })
              proof = r.json()
              proofs.append({
                  "file": file_path,
                  "proof": proof
              })
          
          # Save proofs
          with open('compliance_proofs.json', 'w') as f:
              json.dump(proofs, f, indent=2)
          
          # Upload as artifact
          print(f"::set-output name=compliant::{all_compliant}")
          EOF
        continue-on-error: true
      
      - name: Upload Proof Bundles
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: compliance-proofs
          path: compliance_proofs.json
      
      - name: Comment on PR
        if: failure()
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '❌ Compliance check failed. Please review violations and fix before merging.'
            })
```

---

## GitLab CI

### .gitlab-ci.yml

```yaml
stages:
  - compliance

compliance_check:
  stage: compliance
  image: python:3.10
  services:
    - name: acpg-backend
      # Your ACPG service configuration
  before_script:
    - pip install requests
    - |
      until curl -f http://acpg-backend:6000/api/v1/health; do
        sleep 2
      done
  script:
    - |
      python3 << 'EOF'
      import requests
      import json
      import os
      
      base_url = "http://acpg-backend:6000/api/v1"
      
      # Check all Python files
      for root, dirs, files in os.walk('.'):
          if 'venv' in root or '.git' in root:
              continue
          for file in files:
              if file.endswith('.py'):
                  file_path = os.path.join(root, file)
                  with open(file_path, 'r') as f:
                      code = f.read()
                  
                  r = requests.post(f"{base_url}/enforce", json={
                      "code": code,
                      "language": "python",
                      "max_iterations": 3
                  })
                  
                  result = r.json()
                  if not result['compliant']:
                      print(f"❌ {file_path} failed compliance check")
                      exit(1)
      
      print("✅ All files passed compliance check")
      EOF
  artifacts:
    when: always
    paths:
      - compliance_proofs.json
    expire_in: 30 days
```

---

## Jenkins

### Jenkinsfile

```groovy
pipeline {
    agent any
    
    stages {
        stage('Compliance Check') {
            steps {
                script {
                    sh '''
                        # Start ACPG
                        cd /path/to/acpg
                        ./scripts/start.sh
                        
                        # Wait for service
                        until curl -f http://localhost:6000/api/v1/health; do
                            sleep 2
                        done
                        
                        # Check compliance
                        python3 << 'EOF'
                        import requests
                        import os
                        
                        base_url = "http://localhost:6000/api/v1"
                        
                        for root, dirs, files in os.walk('.'):
                            if 'venv' in root or '.git' in root:
                                continue
                            for file in files:
                                if file.endswith('.py'):
                                    file_path = os.path.join(root, file)
                                    with open(file_path, 'r') as f:
                                        code = f.read()
                                    
                                    r = requests.post(f"{base_url}/enforce", json={
                                        "code": code,
                                        "language": "python"
                                    })
                                    
                                    if not r.json()['compliant']:
                                        print(f"❌ {file_path} failed")
                                        exit(1)
                        EOF
                    '''
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'compliance_proofs.json', allowEmptyArchive: true
        }
    }
}
```

---

## Docker-based CI

### Dockerfile for CI

```dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install ACPG dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install ACPG
COPY . /app/acpg

# Install ACPG CLI tools
RUN pip install -e /app/acpg/backend

# Copy compliance check script
COPY check_compliance.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/check_compliance.sh

ENTRYPOINT ["check_compliance.sh"]
```

### check_compliance.sh

```bash
#!/bin/bash
set -e

# Start ACPG
cd /app/acpg
./scripts/start.sh

# Wait for service
until curl -f http://localhost:6000/api/v1/health; do
    sleep 2
done

# Check all files
python3 << 'EOF'
import requests
import os
import sys

base_url = "http://localhost:6000/api/v1"
failed = []

for root, dirs, files in os.walk('/code'):
    if 'venv' in root or '.git' in root:
        continue
    for file in files:
        if file.endswith('.py'):
            file_path = os.path.join(root, file)
            with open(file_path, 'r') as f:
                code = f.read()
            
            r = requests.post(f"{base_url}/enforce", json={
                "code": code,
                "language": "python"
            })
            
            if not r.json()['compliant']:
                print(f"❌ {file_path} failed")
                failed.append(file_path)

if failed:
    print(f"\n❌ {len(failed)} files failed compliance check")
    sys.exit(1)
else:
    print("✅ All files passed compliance check")
EOF
```

---

## Pre-commit Hook

### .pre-commit-config.yaml

```yaml
repos:
  - repo: local
    hooks:
      - id: acpg-compliance
        name: ACPG Compliance Check
        entry: bash -c 'python3 << EOF
import requests
import sys

base_url = "http://localhost:6000/api/v1"

for file in sys.argv[1:]:
    with open(file, "r") as f:
        code = f.read()
    
    r = requests.post(f"{base_url}/enforce", json={
        "code": code,
        "language": "python"
    })
    
    if not r.json()["compliant"]:
        print(f"❌ {file} failed compliance check")
        sys.exit(1)

print("✅ All files passed compliance check")
EOF'
        language: system
        files: \.py$
        pass_filenames: true
```

### Git Hook (direct)

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Start ACPG if not running
if ! curl -f http://localhost:6000/api/v1/health > /dev/null 2>&1; then
    cd /path/to/acpg
    ./scripts/start.sh
    sleep 5
fi

# Check staged files
for file in $(git diff --cached --name-only --diff-filter=ACM | grep '\.py$'); do
    code=$(git show :"$file")
    response=$(curl -s -X POST http://localhost:6000/api/v1/enforce \
        -H "Content-Type: application/json" \
        -d "{\"code\": $(echo "$code" | jq -Rs .), \"language\": \"python\"}")
    
    if [ "$(echo "$response" | jq -r '.compliant')" != "true" ]; then
        echo "❌ $file failed compliance check"
        echo "$response" | jq '.violations'
        exit 1
    fi
done

echo "✅ All staged files passed compliance check"
```

---

## Kubernetes CI/CD

### Tekton Task

```yaml
apiVersion: tekton.dev/v1beta1
kind: Task
metadata:
  name: acpg-compliance-check
spec:
  params:
    - name: code-path
      description: Path to code directory
    - name: language
      default: python
  steps:
    - name: check-compliance
      image: python:3.10
      script: |
        pip install requests
        python3 << 'EOF'
        import requests
        import os
        
        base_url = os.environ.get('ACPG_URL', 'http://acpg-service:6000/api/v1')
        code_path = "$(params.code-path)"
        
        for root, dirs, files in os.walk(code_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r') as f:
                        code = f.read()
                    
                    r = requests.post(f"{base_url}/enforce", json={
                        "code": code,
                        "language": "python"
                    })
                    
                    if not r.json()['compliant']:
                        print(f"❌ {file_path} failed")
                        exit(1)
        EOF
```

---

## Best Practices

### 1. Fail Fast

- Check compliance early in the pipeline
- Fail on first violation to save time
- Provide clear error messages

### 2. Proof Bundle Storage

- Store proof bundles as artifacts
- Include in release packages
- Archive for audit purposes

### 3. Parallel Execution

- Check multiple files in parallel
- Use ACPG's parallel tool execution
- Optimize for CI/CD time limits

### 4. Caching

- Cache ACPG service startup
- Reuse proof bundles when code unchanged
- Cache tool results

### 5. Notifications

- Notify on compliance failures
- Include violation details
- Link to proof bundles

---

## Example: Full Pipeline

```yaml
name: Full CI/CD Pipeline

on:
  pull_request:
  push:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run tests
        run: pytest
  
  compliance:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v3
      - name: Compliance Check
        run: |
          # Start ACPG
          ./scripts/start.sh
          
          # Check compliance
          python3 check_compliance.py
      
      - name: Generate Proof Bundle
        if: success()
        run: |
          python3 generate_proofs.py
      
      - name: Upload Proofs
        uses: actions/upload-artifact@v3
        with:
          name: compliance-proofs
          path: proofs/
  
  build:
    runs-on: ubuntu-latest
    needs: compliance
    steps:
      - name: Build
        run: docker build -t app .
  
  deploy:
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'
    steps:
      - name: Deploy
        run: ./deploy.sh
```

---

## Troubleshooting

### Service Not Available

```bash
# Check if ACPG is running
curl http://localhost:6000/api/v1/health

# Start if needed
cd /path/to/acpg
./scripts/start.sh
```

### Timeout Issues

- Increase CI/CD timeout
- Use parallel execution
- Cache results

### Network Issues

- Use service names in containers
- Check firewall rules
- Verify port accessibility

---

## Summary

ACPG integrates seamlessly with:
- ✅ GitHub Actions
- ✅ GitLab CI
- ✅ Jenkins
- ✅ Docker-based CI
- ✅ Pre-commit hooks
- ✅ Kubernetes CI/CD

**Key Benefits**:
- Automated compliance checking
- Proof bundle generation
- Early failure detection
- Audit trail preservation

