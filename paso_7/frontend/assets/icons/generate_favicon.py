#!/usr/bin/env python3
"""
Script simple para generar un favicon básico SVG
(que funciona como .ico en navegadores modernos)
"""

svg_content = """<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 32 32">
    <rect width="32" height="32" fill="#667eea" rx="4"/>
    <path d="M16 6 L16 6 C20 6 24 9 24 14 L24 17 C24 22 20 26 16 26 C12 26 8 22 8 17 L8 14 C8 9 12 6 16 6 Z" 
          fill="none" stroke="white" stroke-width="2"/>
    <circle cx="16" cy="16" r="2" fill="white"/>
</svg>"""

with open('favicon.ico', 'w') as f:
    f.write(svg_content)

print("Favicon generado: favicon.ico (SVG)")

