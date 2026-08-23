---
trigger: model_decision
description: when using google-jules
---

Usage
The CLI is built around commands and subcommands. You can get help for any command by using the -h or —help flag.

# Get general help
jules help

# Get help for a specific command (e.g., remote)
jules remote --help

Global Flags
-h, --help: Displays help information for jules or a specific command.

--theme <string>: Sets the theme for the terminal user interface (TUI). Options are dark (default) or light.

Example: jules --theme light

Available Commands
version

Shows the currently installed version of the Jules Tools CLI.

jules version

remote

The remote command is the primary way to interact with Jules sessions running in the cloud. It has several subcommands.

remote list Lists your connected repositories or active sessions.

--repo: Flag to list all repositories connected to Jules.

--session: Flag to list all your remote sessions.

Examples:

# List all connected repositories
jules remote list --repo

# List all active and past sessions
jules remote list --session

remote new

Creates a new remote session to delegate a task to Jules.

Jules can automatically infer the repository from your current working directory, so you can often omit the --repo flag.

--repo <repo_name>: Specifies the repository for the session (e.g., torvalds/linux or . for the current directory’s repo).

--session "<prompt>": A string describing the task for Jules to perform.

--parallel <number>: Starts multiple parallel sessions to work on the same task.

Example:

# Start a new session to write unit tests in the 'torvalds/linux' repo
jules remote new --repo torvalds/linux --session "write unit tests"

remote pull

Pulls the results (e.g., code changes) from a completed session.

--session <session_id>: The ID of the session you want to pull.
Example:

# Pull the results for session ID 123456
jules remote pull --session 123456

completion

Generates an autocompletion script for your shell (e.g., bash, zsh) to enable tab completion for jules commands.

# Generate completion script for bash
jules completion bash
