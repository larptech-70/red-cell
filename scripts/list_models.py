"""Print the model IDs your Token Factory key can use (confirm Nemotron IDs before a live run)."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from redcell.core.llm import TokenFactory
tf = TokenFactory()
if not tf.live: sys.exit("Set NEBIUS_API_KEY first (see .env.example).")
print("\n".join(m for m in tf.models() if "nemotron" in m.lower()))
