import os
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS
import traceback
from transformers import pipeline
import re
import sys
import ast
import autopep8
import difflib
import base64
from github import Github
import time

app = Flask(__name__)
CORS(app)

# Hugging Face API token (replace with your actual token)
HF_API_TOKEN = "HF_API_TOKEN"

# GitHub API token (replace with your actual token)
GITHUB_API_TOKEN = "GITHUB_API_TOKEN"

# Initialize the classification pipeline
try:
    classifier = pipeline("text-classification", model="distilbert-base-uncased")
except Exception as e:
    print(f"Error initializing classifier: {str(e)}")
    print(traceback.format_exc())
    sys.exit(1)

# Vulnerability patterns with descriptions, risk levels, and remediation suggestions
VULNERABILITY_PATTERNS = {
    'sql_injection': {
        'pattern': r'SELECT.*FROM.*WHERE',
        'description': 'SQL Injection vulnerability detected. This could allow an attacker to manipulate your database queries.',
        'risk_level': 'High',
        'severity_score': 8,
        'remediation': 'Use parameterized queries or prepared statements instead of concatenating user input directly into SQL queries.',
        'resource': 'https://owasp.org/www-community/attacks/SQL_Injection'
    },
    'xss': {
        'pattern': r'<script>.*</script>',
        'description': 'Cross-Site Scripting (XSS) vulnerability detected. This could allow an attacker to inject malicious scripts into your web pages.',
        'risk_level': 'High',
        'severity_score': 7,
        'remediation': 'Sanitize and validate all user input before rendering it in HTML. Use content security policies and output encoding.',
        'resource': 'https://owasp.org/www-community/attacks/xss/'
    },
    'command_injection': {
        'pattern': r'exec\(|system\(|shell_exec\(',
        'description': 'Command Injection vulnerability detected. This could allow an attacker to execute arbitrary commands on your system.',
        'risk_level': 'Critical',
        'severity_score': 9,
        'remediation': 'Avoid using user input in system commands. If necessary, use a whitelist of allowed commands and sanitize user input.',
        'resource': 'https://owasp.org/www-community/attacks/Command_Injection'
    },
    'path_traversal': {
        'pattern': r'\.\./',
        'description': 'Path Traversal vulnerability detected. This could allow an attacker to access files outside the intended directory.',
        'risk_level': 'Medium',
        'severity_score': 6,
        'remediation': 'Validate and sanitize file paths. Use a whitelist of allowed directories and files.',
        'resource': 'https://owasp.org/www-community/attacks/Path_Traversal'
    },
}

def rule_based_analysis(code):
    vulnerabilities = []
    for vuln_type, vuln_info in VULNERABILITY_PATTERNS.items():
        matches = re.finditer(vuln_info['pattern'], code, re.IGNORECASE)
        for match in matches:
            vulnerabilities.append({
                'type': vuln_type,
                'description': vuln_info['description'],
                'risk_level': vuln_info['risk_level'],
                'severity_score': vuln_info['severity_score'],
                'remediation': vuln_info['remediation'],
                'resource': vuln_info['resource'],
                'line_number': code[:match.start()].count('\n') + 1,
                'code_snippet': code[max(0, match.start() - 50):min(len(code), match.end() + 50)]
            })
    return vulnerabilities

def correct_vulnerabilities(code, vulnerabilities):
    try:
        tree = ast.parse(code)
        corrector = VulnerabilityCorrector(vulnerabilities)
        corrected_tree = corrector.visit(tree)
        return ast.unparse(corrected_tree)
    except Exception as e:
        app.logger.error(f"Error correcting vulnerabilities: {str(e)}")
        return code

class VulnerabilityCorrector(ast.NodeTransformer):
    def __init__(self, vulnerabilities):
        self.vulnerabilities = vulnerabilities

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id in ['exec', 'eval']:
                # Replace exec() and eval() with safer alternatives
                return ast.parse('print("Unsafe function call removed")').body[0]
        return node

    def visit_Str(self, node):
        # Check for potential XSS in string literals
        if '<script>' in node.s:
            return ast.Str(s=node.s.replace('<script>', '').replace('</script>', ''))
        return node

    # Add more visit methods for other vulnerability types

def correct_code(code, vulnerabilities):
    try:
        # First, correct vulnerabilities
        code = correct_vulnerabilities(code, vulnerabilities)
        # Then, format the code
        code = autopep8.fix_code(code)
        return code
    except Exception as e:
        app.logger.error(f"Error correcting code: {str(e)}")
        return code

def generate_diff(original, corrected):
    d = difflib.unified_diff(original.splitlines(), corrected.splitlines(), lineterm='', n=3)
    return '\n'.join(d)

@app.route('/analyze_code', methods=['POST'])
def analyze_code():
    try:
        data = request.json
        code = data.get('code', '')
        language = data.get('language', '')

        if not code:
            return jsonify({"error": "Please provide code to analyze."}), 400

        # Rule-based analysis
        rule_based_result = rule_based_analysis(code)

        # Correct the code
        corrected_code = correct_code(code, rule_based_result)

        # ML-based analysis
        ml_result = classifier(corrected_code)[0]

        # Determine overall risk
        risk_levels = [vuln['risk_level'] for vuln in rule_based_result]
        if 'Critical' in risk_levels:
            overall_risk = 'Critical'
        elif 'High' in risk_levels or ml_result['score'] > 0.7:
            overall_risk = 'High'
        elif 'Medium' in risk_levels or ml_result['score'] > 0.4:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'

        # Generate a diff between original and corrected code
        diff = generate_diff(code, corrected_code)

        # Sort vulnerabilities by severity score
        rule_based_result.sort(key=lambda x: x['severity_score'], reverse=True)

        # Combine results
        analysis = {
            "ml_analysis": ml_result,
            "rule_based_analysis": rule_based_result,
            "overall_risk": overall_risk,
            "original_code": code,
            "corrected_code": corrected_code,
            "diff": diff,
            "language": language
        }

        return jsonify({"analysis": analysis})
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({"error": f"Unexpected error: {str(e)}", "traceback": traceback.format_exc()}), 500

@app.route('/analyze_github', methods=['POST'])
def analyze_github():
    try:
        data = request.json
        repo_url = data.get('repoUrl', '')

        if not repo_url:
            return jsonify({"error": "Please provide a GitHub repository URL."}), 400

        # Extract owner and repo name from the URL
        parts = repo_url.split('/')
        owner = parts[-2]
        repo_name = parts[-1]

        # Initialize GitHub client
        g = Github(GITHUB_API_TOKEN)
        repo = g.get_repo(f"{owner}/{repo_name}")

        # Analyze each file in the repository
        vulnerabilities = []
        total_files = sum(1 for _ in repo.get_contents(""))
        analyzed_files = 0

        for content_file in repo.get_contents(""):
            if content_file.type == "file":
                file_content = base64.b64decode(content_file.content).decode('utf-8')
                file_vulnerabilities = rule_based_analysis(file_content)
                if file_vulnerabilities:
                    vulnerabilities.append({
                        "file": content_file.path,
                        "vulnerabilities": file_vulnerabilities
                    })
            analyzed_files += 1
            time.sleep(0.1)  # Add a small delay to avoid rate limiting

        # Determine overall risk
        all_risk_levels = [vuln['risk_level'] for file_vuln in vulnerabilities for vuln in file_vuln['vulnerabilities']]
        if 'Critical' in all_risk_levels:
            overall_risk = 'Critical'
        elif 'High' in all_risk_levels:
            overall_risk = 'High'
        elif 'Medium' in all_risk_levels:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'

        # Sort vulnerabilities by severity score
        for file_vuln in vulnerabilities:
            file_vuln['vulnerabilities'].sort(key=lambda x: x['severity_score'], reverse=True)

        # Combine results
        analysis = {
            "overall_risk": overall_risk,
            "vulnerabilities": vulnerabilities,
            "total_files": total_files,
            "analyzed_files": analyzed_files
        }

        return jsonify({"analysis": analysis})
    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        app.logger.error(traceback.format_exc())
        return jsonify({"error": f"Unexpected error: {str(e)}", "traceback": traceback.format_exc()}), 500

if __name__ == '__main__':
    app.run(debug=True)
