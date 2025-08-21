# Contributing to Ethical Hacking Assistant

Thank you for considering contributing to the Ethical Hacking Assistant!

## Code of Conduct
This project adheres to a code of conduct. By participating, you are expected to uphold this code. Please report unacceptable behavior to [contact@example.com].

## How Can I Contribute?
1. **Reporting Bugs:** Use the issue tracker to report bugs.
2. **Feature Requests:** Suggest features through the issue tracker.
3. **Implementation:** Follow the repository structure and submit your changes via pull request.

## Development Workflow
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin feature/my-new-feature`
5. Submit a pull request

## Coding Style
- Follow PEP 8 for Python code
- Use type hints for all function parameters and return values
- Include docstrings for all functions and classes
- Write tests for new functionality

## Adding a New Agent
To add a new agent to the Ethical Hacking Assistant, follow these steps:

1. Create a new file in the `src/agents` directory with a descriptive name, e.g., `my_new_agent.py`
2. Implement your agent class inheriting from `BaseAgent`
3. Implement the required methods, especially `execute_task`
4. Add agent documentation in `docs/agents`
5. Update the configuration to include your new agent

## Documentation
Every contribution should include appropriate documentation:

- For new features, update the relevant documentation files
- For bug fixes, explain the issue and your solution
- For new agents, create a dedicated documentation file

## Testing
All contributions should include tests:

- For new features, add unit tests in the `tests` directory
- Ensure all existing tests continue to pass
- For new agents, test with different inputs and edge cases

## Pull Request Process
1. Ensure all tests pass
2. Update the documentation if necessary
3. Wait for review from a maintainer
4. Make any requested changes
5. Once approved, a maintainer will merge your contribution

Thank you for your contributions!
