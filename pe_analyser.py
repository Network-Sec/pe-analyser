#!/usr/bin/env python3

import pefile
import os
import sys
import argparse
import tabulate
import subprocess
import platform
import textwrap
from flask import Flask, jsonify, render_template, Response, stream_with_context

def is_windows():
    return platform.system().lower() == "windows"

def is_linux():
    return platform.system().lower() == "linux"

def get_terminal_size():
    try:
        columns, rows = os.get_terminal_size()
    except OSError:
        columns, rows = 80, 24
    return columns, rows

def verify_signature(filepath):
    if is_windows():
        try:
            import win32com.client
            from win32com.client import Dispatch
            obj_Signer = Dispatch("CAPICOM.Signer")
            obj_Signer.Load(filepath, "", 0)
            return obj_Signer.Certificate.SubjectName
        except Exception as e:
            return f"Signature verification failed: {str(e)}"
    elif is_linux():
        result = subprocess.run(['osslsigncode', 'verify', filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.decode() if result.returncode == 0 else "No valid signature found"
    return "Signature verification not supported on this OS."

def analyze_pe(filepath, detail_level='normal'):
    try:
        with open(filepath, 'rb') as current:
            xtract = current.read(2)
            conv = xtract.decode('ascii', errors='ignore')
            if conv != 'MZ':
                return {"error": "Not a PE file (missing 'MZ' header)"}

        pe = pefile.PE(filepath)
    except pefile.PEFormatError as err:
        return {"error": f"PEFormatError: {err}"}

    pe_info = {}

    # Basic Section Analysis - Always include
    pe_info['Sections'] = []
    for section in pe.sections:
        section_name = section.Name.decode('ascii', errors='ignore').strip()
        pe_info['Sections'].append({
            'Name': section_name,
            'Virtual Address': hex(section.VirtualAddress),
            'Virtual Size': hex(section.Misc_VirtualSize),
            'Raw Size': hex(section.SizeOfRawData),
            'Characteristics': hex(section.Characteristics)
        })

    if detail_level in ['normal', 'long']:
        pe_info['Entry Point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        pe_info['Image Base'] = hex(pe.OPTIONAL_HEADER.ImageBase)
        pe_info['Subsystem'] = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown")

    if detail_level == 'long':
        pe_info['DLLs Loaded'] = [entry.dll.decode('utf-8') for entry in pe.DIRECTORY_ENTRY_IMPORT] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else []
        pe_info['Exports'] = [exp.name.decode('ascii') for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols if exp.name is not None] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else []
        pe_info['Virtual Memory Sections'] = [
            {
                'Base': hex(section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase),
                'Protection': 'R/W' if section.Characteristics & 0x80000000 else 'R'
            }
            for section in pe.sections
        ]

    pe_info['Signature'] = verify_signature(filepath)
    pe_info['Is Legit'] = "Yes" if "CN=" in pe_info['Signature'] else "No"

    return pe_info

def print_wrapped(text, width):
    """ Print text wrapped to fit within the given width. """
    if len(text) > width:
        return "\n".join(textwrap.wrap(text, width))
    return text

def display_pe_info(pe_info, filename, detail_level='normal'):
    columns, _ = get_terminal_size()

    columns -= 40

    def print_wrapped(text, width):
        """ Print text wrapped to fit within the given width. """
        if len(text) > width:
            return "\n".join(textwrap.wrap(text, width))
        return text

    def truncate_long_list(data_list, max_length=100):
        """ Truncate long lists for display. """
        if isinstance(data_list, list) and len(data_list) > max_length:
            return data_list[:max_length] + ['... (truncated)']
        return data_list

    if 'error' in pe_info:
        print_wrapped(f"Error processing '{filename}': {pe_info['error']}", columns)
        return

    # Print filename first
    print(f"\nAnalyzing {filename}\n")

    headers = ['Attribute', 'Value']
    rows = []
    for k, v in pe_info.items():
        if k == 'DLLs Loaded' or k == 'Exports':
            v = truncate_long_list(v)
        rows.append((k, print_wrapped(str(v), columns)))

    # Display the basic information
    print(tabulate.tabulate(rows, headers=headers, tablefmt='grid'))

    # Display section details if present
    if 'Sections' in pe_info:
        print_wrapped("\nSections:\n" + "-"*columns, columns)
        headers = ['Name', 'Virtual Address', 'Virtual Size', 'Raw Size', 'Characteristics']
        rows = [(s['Name'], s['Virtual Address'], s['Virtual Size'], s['Raw Size'], s['Characteristics']) for s in pe_info['Sections']]
        print(tabulate.tabulate(rows, headers=headers, tablefmt='grid'))


def analyze_directory(dirpath, detail_level):
    for dirpath, _, filenames in os.walk(dirpath):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            with open(filepath, 'rb') as current:
                xtract = current.read(2)
                conv = xtract.decode('ascii', errors='ignore')
                if conv == 'MZ':
                    pe_info = analyze_pe(filepath, detail_level)
                    display_pe_info(pe_info, filepath, detail_level)

def start_flask_server(base_dirpath, detail_level):
    app = Flask(__name__)

    @app.route("/")
    def index():
        return render_template('index.html')  # Render an initial empty page

    @app.route("/stream")
    def stream():
        def generate():
            for dirpath, _, filenames in os.walk(base_dirpath):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    with open(filepath, 'rb') as current:
                        xtract = current.read(2)
                        conv = xtract.decode('ascii', errors='ignore')
                        if conv == 'MZ':
                            pe_info = analyze_pe(filepath, detail_level)
                            
                            # Start building the HTML output
                            html_output = f"<div class='file-analysis'><h3>{filename}</h3>"
                            
                            # Table for Sections
                            if 'Sections' in pe_info:
                                sections = pe_info['Sections']
                                html_output += "<h4>Sections</h4>"
                                html_output += "<table class='table table-striped'><thead><tr>"
                                html_output += "<th>Name</th><th>Virtual Address</th><th>Virtual Size</th><th>Raw Size</th><th>Characteristics</th></tr></thead><tbody>"
                                for section in sections:
                                    html_output += f"<tr><td>{section.get('Name', '')}</td><td>{section.get('Virtual Address', '')}</td><td>{section.get('Virtual Size', '')}</td><td>{section.get('Raw Size', '')}</td><td>{section.get('Characteristics', '')}</td></tr>"
                                html_output += "</tbody></table>"

                            # Table for Virtual Memory Sections
                            if 'Virtual Memory Sections' in pe_info:
                                vms = pe_info['Virtual Memory Sections']
                                html_output += "<h4>Virtual Memory Sections</h4>"
                                html_output += "<table class='table table-striped'><thead><tr>"
                                html_output += "<th>Base</th><th>Protection</th></tr></thead><tbody>"
                                for section in vms:
                                    html_output += f"<tr><td>{section.get('Base', '')}</td><td>{section.get('Protection', '')}</td></tr>"
                                html_output += "</tbody></table>"

                            # Table for DLLs Loaded
                            if 'DLLs Loaded' in pe_info:
                                dlls = pe_info['DLLs Loaded']
                                html_output += "<h4>DLLs Loaded</h4>"
                                html_output += "<table class='table table-striped'><thead><tr><th>DLL Name</th></tr></thead><tbody>"
                                for dll in dlls:
                                    html_output += f"<tr><td>{dll}</td></tr>"
                                html_output += "</tbody></table>"

                            # Table for Signature and Legitimacy
                            if 'Signature' in pe_info or 'Is Legit' in pe_info:
                                html_output += "<h4>Signature & Legitimacy</h4>"
                                html_output += "<table class='table table-striped'><thead><tr>"
                                html_output += "<th>Attribute</th><th>Value</th></tr></thead><tbody>"
                                if 'Signature' in pe_info:
                                    html_output += f"<tr><td>Signature</td><td>{pe_info['Signature']}</td></tr>"
                                if 'Is Legit' in pe_info:
                                    html_output += f"<tr><td>Is Legit</td><td>{pe_info['Is Legit']}</td></tr>"
                                html_output += "</tbody></table>"
                                
                            html_output += "</div>"
                            yield f"data: {html_output}\n\n"

        return Response(stream_with_context(generate()), content_type='text/event-stream')

    app.run(host="127.0.0.1", port=5000)

def main():
    parser = argparse.ArgumentParser(description="PE File Analyzer")
    parser.add_argument('path', help="File or directory to analyze")
    parser.add_argument('-s', '--short', action='store_true', help="Display short information")
    parser.add_argument('-l', '--long', action='store_true', help="Display detailed information")
    parser.add_argument('--flask', action='store_true', help="Start a Flask server to display results")

    args = parser.parse_args()

    if args.short:
        detail_level = 'short'
    elif args.long:
        detail_level = 'long'
    else:
        detail_level = 'normal'

    if os.path.isfile(args.path):
        pe_info = analyze_pe(args.path, detail_level)
        display_pe_info(pe_info, args.path, detail_level)
    elif os.path.isdir(args.path):
        if args.flask:
            start_flask_server(args.path, detail_level)
        else:
            analyze_directory(args.path, detail_level)
    else:
        print(f"Path '{args.path}' does not exist or is not a valid file/directory")

if __name__ == "__main__":
    main()
