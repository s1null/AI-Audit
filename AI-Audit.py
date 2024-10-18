import argparse
from datetime import datetime
import os
from rich import print as rich_print
from openai import OpenAI
import time
from tqdm import tqdm
from textwrap import wrap
from rich.console import Console
import json
import re
from pathlib import Path

# Initialize OpenAI client
console = Console()
client = OpenAI(base_url="http://localhost:1234/v1", api_key="not-needed")

def parse_vulnerability(response_text, chunk_start):
    """Parse vulnerability response into structured format."""
    vulnerabilities = []
    if response_text == "SECURE":
        return []

    # Split by vulnerability delimiter
    vuln_sections = response_text.split("VULNERABILITY@@")
    for section in vuln_sections[1:]:  # Skip the first empty split
        vuln = {}
        lines = section.strip().split("\n")
        for line in lines:
            if ": " in line:
                key, value = line.split(": ", 1)
                if key.strip() in ['Location', 'Severity', 'Category', 'Affected Code']:
                    vuln[key.strip()] = value.strip()

        # Adjust the location to account for the chunk start
        if 'Location' in vuln:
            try:
                location = int(vuln['Location'])
                vuln['Location'] = str(chunk_start + location)
            except ValueError:
                pass  # If location is not a number, leave it as is

        if vuln:
            vulnerabilities.append(vuln)

    return vulnerabilities

def analyze_security(content, chunk_start):
    completion = client.chat.completions.create(
        model="local-model",
        messages=[
            {
                "role": "system",
                "content": """Perform a comprehensive security vulnerability assessment of the provided code. Follow these strict guidelines:

RESPONSE FORMAT:
- If NO vulnerabilities found: Respond with 'SECURE'
- If vulnerabilities found: Format each finding as:
  VULNERABILITY@@
  Location: [line_number]
  Severity: [CRITICAL|HIGH|MEDIUM|LOW]
  Category: [OWASP Category or Common Weakness Enumeration (CWE) ID]
  Affected Code: `relevant code snippet`
  @@

ANALYSIS REQUIREMENTS:
1. Check for but not limited to:
   - Injection vulnerabilities (SQL, NoSQL, Command, etc.)
   - Authentication/Authorization flaws
   - Sensitive data exposure
   - Security misconfiguration
   - Cross-Site Scripting (XSS)
   - Insecure deserialization
   - Known vulnerable dependencies
   - Buffer overflows
   - Race conditions
   - Cryptographic failures

2. Consider context:
   - Programming language specific vulnerabilities
   - Framework-specific security issues
   - Environment variables handling
   - Input validation
   - Output encoding
   - Security controls implementation

3. False Positive Reduction:
   - Validate if the identified issue is exploitable
   - Consider existing security controls
   - Check for sanitization mechanisms
   - Verify the impact in the given context

4. IMPORTANT: Always provide the exact line number for each vulnerability in the Location field. The line number should be relative to the start of the provided code chunk."""
            },
            {"role": "user", "content": content}
        ],
        temperature=0.7,
    )
    return completion.choices[0].message

def generate_html(scan_results, timestamp):
    # Convert scan results to JSON string safely
    json_data = json.dumps(scan_results)
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Scan Results - {timestamp}</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.min.css" rel="stylesheet">
        <link href="https://cdn.datatables.net/buttons/2.2.2/css/buttons.dataTables.min.css" rel="stylesheet">
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <script src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.min.js"></script>
        <script src="https://cdn.datatables.net/buttons/2.2.2/js/dataTables.buttons.min.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.1.3/jszip.min.js"></script>
        <script src="https://cdn.datatables.net/buttons/2.2.2/js/buttons.html5.min.js"></script>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.5.1/styles/github.min.css">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.5.1/highlight.min.js"></script>
        <style>
            .severity-critical {{ background-color: #fee2e2; }}
            .severity-high {{ background-color: #fef3c7; }}
            .severity-medium {{ background-color: #fef9c3; }}
            .severity-low {{ background-color: #ecfdf5; }}
        </style>
    </head>
    <body class="bg-gray-50">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
            <h1 class="text-4xl font-bold mb-8 text-center text-indigo-700">Security Scan Results</h1>
            <div class="mb-8 text-center text-gray-600">Scan completed: {timestamp}</div>
            
            <div class="bg-white rounded-lg shadow-lg overflow-hidden p-6">
                <div class="mb-6">
                    <h2 class="text-2xl font-semibold text-indigo-600">Summary</h2>
                    <div id="summary" class="grid grid-cols-4 gap-4 mt-4">
                    </div>
                </div>
                
                <div>
                    <h2 class="text-2xl font-semibold mb-4 text-indigo-600">Detailed Findings</h2>
                    <table id="vulnerabilitiesTable" class="w-full">
                        <thead>
                            <tr>
                                <th>File</th>
                                <th>Location</th>
                                <th>Severity</th>
                                <th>Category</th>
                                <th>Affected Code</th>
                            </tr>
                        </thead>
                        <tbody>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <script>
        const results = {json_data};
        
        document.addEventListener('DOMContentLoaded', function() {{
            // Calculate summary
            const summary = {{
                critical: 0,
                high: 0,
                medium: 0,
                low: 0
            }};
            
            results.forEach(vuln => {{
                const severity = vuln.Severity.toLowerCase();
                if (summary.hasOwnProperty(severity)) {{
                    summary[severity]++;
                }}
            }});
            
            // Update summary display
            const summaryDiv = document.getElementById('summary');
            const severityClasses = {{
                critical: 'bg-red-100',
                high: 'bg-orange-100',
                medium: 'bg-yellow-100',
                low: 'bg-green-100'
            }};
            
            Object.entries(summary).forEach(([severity, count]) => {{
                summaryDiv.innerHTML += `
                    <div class="p-4 rounded-lg ${{severityClasses[severity]}}">
                        <div class="text-lg font-semibold capitalize">${{severity}}</div>
                        <div class="text-2xl font-bold">${{count}}</div>
                    </div>
                `;
            }});

            // Initialize DataTable
            $('#vulnerabilitiesTable').DataTable({{
                data: results,
                columns: [
                    {{ data: 'Location', render: function(data) {{ return data.split(':')[0]; }}}},
                    {{ data: 'Location', render: function(data) {{ return data.split(':')[1] || ''; }}}},
                    {{ 
                        data: 'Severity',
                        render: function(data) {{
                            const classes = {{
                                'CRITICAL': 'severity-critical',
                                'HIGH': 'severity-high',
                                'MEDIUM': 'severity-medium',
                                'LOW': 'severity-low'
                            }};
                            return `<span class="px-2 py-1 rounded ${{classes[data.toUpperCase()]}}">${{data}}</span>`;
                        }}
                    }},
                    {{ data: 'Category' }},
                    {{ 
                        data: 'Affected Code',
                        render: function(data) {{
                            return `<pre><code class="language-python">${{data.replace(/`/g, '')}}</code></pre>`;
                        }}
                    }}
                ],
                pageLength: 10,
                dom: 'Bfrtip',
                buttons: ['csv', 'excel'],
                drawCallback: function() {{
                    document.querySelectorAll('pre code').forEach(block => {{
                        hljs.highlightElement(block);
                    }});
                }}
            }});
        }});
        </script>
    </body>
    </html>
    """
    return html_content
def scan_file(file_path, scan_results):
    console.print(f"[bold blue]Scanning[/bold blue]: {file_path}")
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.readlines()

    total_chunks = (len(content) - 1) // 100 + 1
    file_vulnerabilities = []

    for chunk_start in range(0, len(content), 100):
        chunk_end = min(chunk_start + 100, len(content))
        code_chunk = ''.join(content[chunk_start:chunk_end])
        response = analyze_security(code_chunk, chunk_start + 1)
        
        if hasattr(response, 'content'):
            results = response.content
        else:
            results = str(response)

        vulnerabilities = parse_vulnerability(results, chunk_start + 1)
        
        for vuln in vulnerabilities:
            if 'Location' in vuln:
                vuln['Location'] = f"{file_path}:{vuln['Location']}"
            file_vulnerabilities.extend([vuln])

    scan_results.extend(file_vulnerabilities)
    
    for vuln in file_vulnerabilities:
        console.print(f"[bold red]Vulnerability Found[/bold red]")
        for key, value in vuln.items():
            console.print(f"[bold yellow]{key}[/bold yellow]: {value}")
        console.print("")

    return file_vulnerabilities

def normalize_path(path):
    """Normalize the given path to handle both relative and absolute paths."""
    return str(Path(path).resolve())

def scan_directory(directory, file_types=None, scan_all=False):
    directory_path = Path(normalize_path(directory))

    if not directory_path.exists():
        console.print(f"[bold red]Error:[/bold red] Directory '{directory}' does not exist")
        return []

    # Use Path.rglob() to find files
    if scan_all:
        files_to_scan = [str(p) for p in directory_path.rglob('*') if p.is_file()]
    else:
        files_to_scan = [str(p) for ext in file_types for p in directory_path.rglob(f'*{ext}') if p.is_file()]

    if not files_to_scan:
        console.print(f"[bold yellow]Warning:[/bold yellow] No files found to scan in '{directory}'")
        return []

    console.print(f"[bold magenta]Total files to scan:[/bold magenta] {len(files_to_scan)}")

    scan_results = []
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = Path(f"./security_scan_results_{timestamp}.html")

    # Scan files and generate results
    for file_path in tqdm(files_to_scan, desc="Scanning files"):
        try:
            scan_file(file_path, scan_results)
        except Exception as e:
            console.print(f"[bold red]Error scanning {file_path}:[/bold red] {e}")

    # Save HTML report
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(generate_html(scan_results, timestamp))

    console.print(f"[bold green]Results saved to:[/bold green] {output_file}")
    return scan_results

def main():
    parser = argparse.ArgumentParser(description="Security vulnerability scanner for source code")
    parser.add_argument("directory", type=str, help="Directory to scan")

    parser.add_argument("--file-types", type=str, nargs="+", default=[".py"],
                        help="File types to scan (e.g., .py .js)")
    parser.add_argument("--all", action="store_true", help="Scan all files regardless of type")

    args = parser.parse_args()
    directory = normalize_path(args.directory)

    console.print(f"[bold blue]Starting scan of directory:[/bold blue] {directory}")
    if not args.all:
        console.print(f"[bold blue]File types to scan:[/bold blue] {', '.join(args.file_types)}")

    start_time = time.time()
    scan_results = scan_directory(directory, args.file_types, scan_all=args.all)

    elapsed_time = time.time() - start_time
    console.print(f"[bold green]Scan completed in {elapsed_time:.2f} seconds[/bold green]")
    console.print(f"[bold yellow]Total vulnerabilities found:[/bold yellow] {len(scan_results)}")

if __name__ == "__main__":
    main()