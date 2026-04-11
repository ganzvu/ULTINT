import sys
import os

# Ensure the project root is on sys.path so both `core.*` and `src.*` can be imported.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
