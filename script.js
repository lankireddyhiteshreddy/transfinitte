document.addEventListener('DOMContentLoaded', () => {
    const analysisType = document.getElementById('analysisType');
    const codeInputSection = document.getElementById('codeInputSection');
    const githubInputSection = document.getElementById('githubInputSection');
    const codeInput = document.getElementById('codeInput');
    const githubInput = document.getElementById('githubInput');
    const languageSelect = document.getElementById('languageSelect');
    const analyzeButton = document.getElementById('analyzeButton');
    const results = document.getElementById('results');
    const correctedCodeSection = document.getElementById('correctedCodeSection');
    const correctedCode = document.getElementById('correctedCode');
    const copyCodeButton = document.getElementById('copyCodeButton');

    analysisType.addEventListener('change', () => {
        if (analysisType.value === 'code') {
            codeInputSection.style.display = 'block';
            githubInputSection.style.display = 'none';
        } else {
            codeInputSection.style.display = 'none';
            githubInputSection.style.display = 'block';
        }
    });

    analyzeButton.addEventListener('click', async () => {
        let data;
        if (analysisType.value === 'code') {
            const code = codeInput.value.trim();
            const language = languageSelect.value;
            if (!code) {
                alert('Please enter some code to analyze.');
                return;
            }
            data = { code, language };
        } else {
            const repoUrl = githubInput.value.trim();
            if (!repoUrl) {
                alert('Please enter a GitHub repository URL.');
                return;
            }
            data = { repoUrl };
        }

        results.innerHTML = 'Analyzing...';
        correctedCodeSection.style.display = 'none';

        try {
            const endpoint = analysisType.value === 'code' ? '/analyze_code' : '/analyze_github';
            const response = await axios.post(`http://127.0.0.1:5000${endpoint}`, data);
            results.innerHTML = formatResults(response.data.analysis, analysisType.value);
            
            if (analysisType.value === 'code') {
                correctedCode.textContent = response.data.analysis.corrected_code;
                correctedCodeSection.style.display = 'block';
                hljs.highlightBlock(correctedCode);
            }
        } catch (error) {
            console.error('Error:', error);
            results.innerHTML = `Error: ${error.response?.data?.error || error.message}`;
        }
    });

    copyCodeButton.addEventListener('click', () => {
        navigator.clipboard.writeText(correctedCode.textContent).then(() => {
            alert('Corrected code copied to clipboard!');
        });
    });

    function formatResults(analysis, type) {
        let html = '<h3>Vulnerability Analysis Results:</h3>';
        html += `<p>Overall Risk: <strong class="vulnerability-${analysis.overall_risk.toLowerCase()}">${analysis.overall_risk}</strong></p>`;
        
        if (type === 'code') {
            html += '<h4>Machine Learning Analysis:</h4>';
            html += `<p>Label: ${analysis.ml_analysis.label}</p>`;
            html += `<p>Confidence Score: ${(analysis.ml_analysis.score * 100).toFixed(2)}%</p>`;
            
            html += '<h4>Rule-Based Analysis:</h4>';
            if (analysis.rule_based_analysis.length > 0) {
                html += '<ul>';
                analysis.rule_based_analysis.forEach(vuln => {
                    html += `
                        <li class="vulnerability-${vuln.risk_level.toLowerCase()}">
                            <strong>${vuln.type}</strong> (Risk Level: ${vuln.risk_level}, Severity Score: ${vuln.severity_score})<br>
                            ${vuln.description}<br>
                            <strong>Remediation:</strong> ${vuln.remediation}<br>
                            <strong>Resource:</strong> <a href="${vuln.resource}" target="_blank">Learn more</a><br>
                            <strong>Line Number:</strong> ${vuln.line_number}<br>
                            <strong>Code Snippet:</strong>
                            <pre class="code-snippet"><code>${highlightVulnerability(vuln.code_snippet, vuln.type)}</code></pre>
                        </li>
                    `;
                });
                html += '</ul>';
            } else {
                html += '<p>No known vulnerabilities detected.</p>';
            }

            html += '<h4>Diff:</h4>';
            html += `<pre><code class="diff">${analysis.diff}</code></pre>`;
        } else {
            html += `<p>Total Files: ${analysis.total_files}</p>`;
            html += `<p>Analyzed Files: ${analysis.analyzed_files}</p>`;
            
            if (analysis.vulnerabilities.length > 0) {
                html += '<h4>Vulnerabilities by File:</h4>';
                analysis.vulnerabilities.forEach(fileVuln => {
                    html += `<h5>${fileVuln.file}</h5>`;
                    html += '<ul>';
                    fileVuln.vulnerabilities.forEach(vuln => {
                        html += `
                            <li class="vulnerability-${vuln.risk_level.toLowerCase()}">
                                <strong>${vuln.type}</strong> (Risk Level: ${vuln.risk_level}, Severity Score: ${vuln.severity_score})<br>
                                ${vuln.description}<br>
                                <strong>Remediation:</strong> ${vuln.remediation}<br>
                                <strong>Resource:</strong> <a href="${vuln.resource}" target="_blank">Learn more</a><br>
                                <strong>Line Number:</strong> ${vuln.line_number}<br>
                                <strong>Code Snippet:</strong>
                                <pre class="code-snippet"><code>${highlightVulnerability(vuln.code_snippet, vuln.type)}</code></pre>
                            </li>
                        `;
                    });
                    html += '</ul>';
                });
            } else {
                html += '<p>No known vulnerabilities detected.</p>';
            }
        }
        
        return html;
    }

    function highlightVulnerability(codeSnippet, vulnType) {
        const pattern = VULNERABILITY_PATTERNS[vulnType].pattern;
        return codeSnippet.replace(new RegExp(pattern, 'gi'), match => `<span class="vulnerability-highlight">${match}</span>`);
    }

    const VULNERABILITY_PATTERNS = {
        'sql_injection': {
            'pattern': 'SELECT.*FROM.*WHERE'
        },
        'xss': {
            'pattern': '<script>.*</script>'
        },
        'command_injection': {
            'pattern': 'exec\\(|system\\(|shell_exec\\('
        },
        'path_traversal': {
            'pattern': '\\.\\.\/'
        }
    };
});
