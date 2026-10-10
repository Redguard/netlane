FROM mcr.microsoft.com/devcontainers/python:3.12-bookworm

# Install uv from Astral's official container image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Persist bash/zsh history
ARG USERNAME=vscode
RUN SNIPPET="export PROMPT_COMMAND='history -a' && export HISTFILE=/commandhistory/.bash_history" \
    && mkdir /commandhistory \
    && touch /commandhistory/.bash_history \
    && touch /commandhistory/.zsh_history \
    && chown -R $USERNAME /commandhistory \
    && echo "$SNIPPET" >> "/home/$USERNAME/.bashrc" \
    && echo "export HISTFILE=/commandhistory/.zsh_history" >> "/home/$USERNAME/.zshrc"

