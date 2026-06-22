# azure-lz-actions

[![Maintained](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/bcgov/azure-lz-actions)

Custom GitHub Actions for B.C. government Azure Landing Zone operations and management.

## Actions

This repository contains reusable GitHub Actions for common Azure infrastructure and security operations.

### Available Actions

- **[nsg-jit-rule](./actions/nsg-jit-rule)** — Create or update Network Security Group (NSG) just-in-time access rules for temporary, secure resource access.

## Repository Structure

```
azure-lz-actions/
├── actions/                          # GitHub Actions directory
│   └── nsg-jit-rule/                # NSG JIT Rule action
│       ├── action.yml               # Action metadata and schema
│       ├── index.js                 # Action implementation
│       ├── package.json             # Node.js dependencies
│       └── README.md                # Action documentation
├── LICENSE                          # Apache 2.0 License
├── README.md                        # This file
├── CONTRIBUTING.md                  # Contribution guidelines
└── CODE_OF_CONDUCT.md              # Community code of conduct
```

## Usage

Each action can be used independently in your GitHub workflows. See the individual action's README for detailed usage instructions and examples.

### General Pattern

```yaml
- uses: bcgov/azure-lz-actions/actions/<action-name>@main
  with:
    # Action-specific inputs
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on:

- Proposing new actions
- Reporting issues
- Submitting pull requests
- Code standards and best practices

## Code of Conduct

Please review our [Code of Conduct](./CODE_OF_CONDUCT.md) to understand community expectations for respectful collaboration.

## License

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

```
http://www.apache.org/licenses/LICENSE-2.0
```

Unless required to applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.