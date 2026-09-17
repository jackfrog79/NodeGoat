"""
JAS SAST demo fixture (Python). Not imported by any app code.

Findings demonstrated:
 - CWE-918 SSRF: outbound request to a user-controlled URL, no allowlist
   (Medium).
 - CWE-1336 Server-Side Template Injection (Jinja2): rendering a template
   string built from user input (High).
 - Prompt-injection-RCE pattern: executing a shell command built from
   untrusted LLM/agent output, one of JFrog's Python-specific AI/agent-risk
   SAST rules (High).
 - CWE-798 Use of hard-coded credentials (Low/Medium).
"""

import subprocess

import requests
from flask import render_template_string

API_KEY = "sk-demo-hardcoded-not-a-real-key-000000"  # Vulnerable: hardcoded credential


def fetch_webhook(user_supplied_url):
    # Vulnerable: SSRF — no validation that the URL points to an allowed host.
    return requests.get(user_supplied_url, timeout=5)


def render_user_greeting(user_supplied_name):
    # Vulnerable: SSTI — user input is compiled as a Jinja2 template, so
    # "{{7*7}}" or a full RCE gadget executes server-side.
    template = "Hello, " + user_supplied_name + "!"
    return render_template_string(template)


def run_agent_suggested_command(llm_output):
    # Vulnerable: prompt-injection-rce — a string produced by an LLM/agent
    # response is executed as a shell command with no allowlist/sandboxing.
    # A malicious or manipulated prompt can smuggle arbitrary shell syntax
    # into llm_output.
    subprocess.run(llm_output, shell=True, check=False)
