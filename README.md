# Ghidra Copilot

Ghidra Copilot is a Ghidra plugin that uses Large Language Models (LLMs) to suggest meaningful names for symbols in your decompiled code. It's designed to accelerate the reverse engineering process by automating the tedious task of renaming variables, functions, and more.

## Features

- **Comprehensive Renaming**: Suggests new names for local variables, function arguments, global variables, labels, and called functions.
- **Context-Aware**: Provides the LLM with as much context as possible—including cross-references for globals and function call bodies—to generate relevant names.
- **Multi-Provider Support**: Works with OpenAI, Anthropic, and Google Gemini models.
- **Interactive**: You choose which types of symbols to rename before the analysis begins.
-
## Demo

Here is a short video demonstrating the script in action:

https://github.com/user-attachments/assets/01111b8d-8a50-4b08-b73a-80af2af194c3

## Installation

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/esauvisky/ghidra-copilot.git
    ```
    (You'll need to replace the URL with the actual one, of course.)

1.  **Set API Keys**:
    You'll need an API key for the LLM provider you want to use. The script will look for it as an environment variable (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `GOOGLE_API_KEY`) or in a file in your home directory (`~/.openai_api_key`, etc.). The script will politely refuse to work without one.

1.  **Add Script Directory to Ghidra**:
    - Open Ghidra and go to **Window -> Script Manager**.
    - Click the **"Script Directories"** icon (looks like a folder with a cog) in the Script Manager toolbar.
    - Click the green **"+"** icon and add the root directory from this cloned repository.
    - Ghidra will now be able to find `GhidraCopilot.py`.

1.  **Refresh Scripts**:
    Click the "Refresh" icon in the Script Manager, or restart Ghidra.

## Usage

1.  Open a program and navigate to a function in the Decompiler view.
2.  Open the **Script Manager** (`Window -> Script Manager`).
3.  Find `GhidraCopilot.py` in your script list (you can filter by name).
4.  Double-click the script to run it.
5.  A dialog will appear asking which symbol types you'd like to rename. Make your selections and click OK.
6.  The script will send the request to the LLM and apply the suggested names. The results are, more often than not, an improvement.

## License

MIT
