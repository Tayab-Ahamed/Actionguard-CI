# Contributing to ActionGuard

Thank you for your interest in contributing to **ActionGuard**! We welcome contributions to help make CI/CD pipelines and Agentic AI workflows safer and more secure.

## Code of Conduct

Please be respectful and constructive in all interactions within this project.

## How Can I Contribute?

- **Reporting Bugs**: Submit an issue with clear reproduction steps and sample workflow syntax.
- **Suggesting Features**: Propose new agentic workflow security rules or integration scanners.
- **Writing Code**: Pick an open issue or submit a pull request with improvements.
- **Improving Documentation**: Fix typos, add examples, or clarify setup instructions.

## Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/<your-username>/Actionguard-CI.git
   cd Actionguard-CI
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\activate
   # Linux/macOS:
   source .venv/bin/activate
   ```

3. Install editable package with dev dependencies:
   ```bash
   pip install -e '.[dev]'
   ```

## Running Tests & Linters

Run the test suite:
```bash
pytest -v
```

Run linting and style checks:
```bash
ruff check .
bandit -r actionguard
```

## Pull Request Guidelines

1. Create a descriptive branch name (e.g. `feat/new-rule`, `fix/cli-parsing`).
2. Ensure all unit tests pass before submitting.
3. Write clean, readable commit messages following conventional commits (`feat:`, `fix:`, `docs:`, `chore:`).
4. Update documentation or tests whenever adding new behavior.