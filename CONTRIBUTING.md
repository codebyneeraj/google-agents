# Contributing to Secure SOC Analyst Orchestrator

Thank you for contributing to the Secure SOC Analyst Orchestrator. This project follows enterprise engineering standards and Google Python Style Guidelines.

## Development Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/codebyneeraj/google-agents.git
   cd google-agents
   ```

2. **Set Up Virtual Environment**:
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # Linux / macOS
   source .venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**:
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```

## Running Tests & Verifications

- Run test suite:
  ```bash
  pytest -v
  ```
- Run cloud validation:
  ```bash
  python validate_cloud.py
  ```
- Run pitch demo:
  ```bash
  python demo.py
  ```

## Conventional Commits

All commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `feat(...)`: New feature or capability
- `fix(...)`: Bug fix or guardrail adjustment
- `test(...)`: Adding or updating test cases
- `docs(...)`: Documentation updates
- `refactor(...)`: Code refactoring without behavior change
- `ci(...)`: Deployment or build pipeline changes
