# mini_siem/__main__.py
# This file allows users to run the tool as:
#     python -m mini_siem run --demo
# This is a Python standard — any package with __main__.py
# can be executed directly with -m flag.

from mini_siem.main import cli

if __name__ == "__main__":
    cli(obj={})