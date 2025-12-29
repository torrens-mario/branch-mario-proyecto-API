#!/bin/bash
echo "🧹 Limpiando archivos compilados y temporales..."
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -type f -name "*.pyc" -delete 2>/dev/null
find . -type f -name "*.pyo" -delete 2>/dev/null
find . -type f -name "*.log" -delete 2>/dev/null
rm -rf venv/ env/ .venv/ 2>/dev/null
echo "✅ Limpieza completada"
