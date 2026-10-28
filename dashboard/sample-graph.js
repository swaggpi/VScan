// Bundled copy of sample-graph.json so the viewer renders on open (file:// cannot fetch local JSON).
// Regenerate: vscan scan samples/vulnerable-app -o dashboard/sample-graph.json, then re-embed.
window.SAMPLE_GRAPH = {
  "version": 1,
  "nodes": [
    {
      "id": "dep:Go:github.com/gin-gonic/gin",
      "kind": "dependency",
      "name": "github.com/gin-gonic/gin",
      "attrs": {
        "ecosystem": "Go",
        "version": "v1.6.0",
        "declared": "v1.6.0",
        "resolved": false,
        "source_file": "go.mod"
      }
    },
    {
      "id": "dep:Go:gopkg.in/yaml.v2",
      "kind": "dependency",
      "name": "gopkg.in/yaml.v2",
      "attrs": {
        "ecosystem": "Go",
        "version": "v2.2.2",
        "declared": "v2.2.2",
        "resolved": false,
        "source_file": "go.mod"
      }
    },
    {
      "id": "dep:Packagist:guzzlehttp/guzzle",
      "kind": "dependency",
      "name": "guzzlehttp/guzzle",
      "attrs": {
        "ecosystem": "Packagist",
        "version": "6.3.0",
        "declared": "6.3.0",
        "resolved": false,
        "source_file": "composer.json"
      }
    },
    {
      "id": "dep:Packagist:monolog/monolog",
      "kind": "dependency",
      "name": "monolog/monolog",
      "attrs": {
        "ecosystem": "Packagist",
        "version": "1.23.0",
        "declared": "1.23.0",
        "resolved": false,
        "source_file": "composer.json"
      }
    },
    {
      "id": "dep:Packagist:phpunit/phpunit",
      "kind": "dependency",
      "name": "phpunit/phpunit",
      "attrs": {
        "ecosystem": "Packagist",
        "version": "6.5.0",
        "declared": "6.5.0",
        "resolved": false,
        "source_file": "composer.json"
      }
    },
    {
      "id": "dep:PyPI:Flask",
      "kind": "dependency",
      "name": "Flask",
      "attrs": {
        "ecosystem": "PyPI",
        "version": "0.12.2",
        "declared": "==0.12.2",
        "resolved": false,
        "source_file": "requirements.txt"
      }
    },
    {
      "id": "dep:PyPI:Jinja2",
      "kind": "dependency",
      "name": "Jinja2",
      "attrs": {
        "ecosystem": "PyPI",
        "version": "2.10",
        "declared": "==2.10",
        "resolved": false,
        "source_file": "requirements.txt"
      }
    },
    {
      "id": "dep:PyPI:PyYAML",
      "kind": "dependency",
      "name": "PyYAML",
      "attrs": {
        "ecosystem": "PyPI",
        "version": "3.13",
        "declared": "==3.13",
        "resolved": false,
        "source_file": "requirements.txt"
      }
    },
    {
      "id": "dep:PyPI:requests",
      "kind": "dependency",
      "name": "requests",
      "attrs": {
        "ecosystem": "PyPI",
        "version": ">=2.20.0",
        "declared": ">=2.20.0",
        "resolved": false,
        "source_file": "requirements.txt"
      }
    },
    {
      "id": "dep:PyPI:urllib3",
      "kind": "dependency",
      "name": "urllib3",
      "attrs": {
        "ecosystem": "PyPI",
        "version": "1.24.1",
        "declared": "==1.24.1",
        "resolved": false,
        "source_file": "requirements.txt"
      }
    },
    {
      "id": "dep:npm:lodash",
      "kind": "dependency",
      "name": "lodash",
      "attrs": {
        "ecosystem": "npm",
        "version": "4.17.4",
        "declared": "^4.17.4",
        "resolved": true,
        "source_file": "frontend/package.json"
      }
    },
    {
      "id": "dep:npm:minimist",
      "kind": "dependency",
      "name": "minimist",
      "attrs": {
        "ecosystem": "npm",
        "version": "1.2.0",
        "declared": "^1.2.0",
        "resolved": true,
        "source_file": "frontend/package.json"
      }
    },
    {
      "id": "doc:README.md",
      "kind": "doc",
      "name": "README.md",
      "attrs": {
        "relpath": "README.md",
        "kind_hint": "prose",
        "excerpt": "# demo app\n\nA small, multi-ecosystem demo target for the VScan scanner. It pins old\ndependencies on purpose and keeps a short, resolvable call chain.\n\n## Endpoints\n\nThe `/import` endpoint accepts uploads from any user and passes the body into\n`load_config`, which parses it as YAML. The `/health`"
      }
    },
    {
      "id": "doc:docs/openapi.yaml",
      "kind": "doc",
      "name": "openapi.yaml",
      "attrs": {
        "relpath": "docs/openapi.yaml",
        "kind_hint": "openapi",
        "excerpt": "openapi: 3.0.0\ninfo:\n  title: Demo API\n  version: 1.0.0\npaths:\n  /import:\n    post:\n      summary: Import configuration from an uploaded body.\n  /health:\n    get:\n      summary: Liveness probe."
      }
    },
    {
      "id": "ep:GET:/health",
      "kind": "entrypoint",
      "name": "GET /health",
      "attrs": {
        "method": "GET",
        "path": "/health",
        "handler": "health",
        "handler_file": "app.py",
        "framework": "flask"
      }
    },
    {
      "id": "ep:POST:/import",
      "kind": "entrypoint",
      "name": "POST /import",
      "attrs": {
        "method": "POST",
        "path": "/import",
        "handler": "import_data",
        "handler_file": "app.py",
        "framework": "flask"
      }
    },
    {
      "id": "file:README.md",
      "kind": "file",
      "name": "README.md",
      "attrs": {
        "relpath": "README.md",
        "language": "markdown",
        "role": "doc",
        "size": 338
      }
    },
    {
      "id": "file:app.py",
      "kind": "file",
      "name": "app.py",
      "attrs": {
        "relpath": "app.py",
        "language": "python",
        "role": "source",
        "size": 794
      }
    },
    {
      "id": "file:composer.json",
      "kind": "file",
      "name": "composer.json",
      "attrs": {
        "relpath": "composer.json",
        "language": "json",
        "role": "manifest",
        "size": 251
      }
    },
    {
      "id": "file:docs/openapi.yaml",
      "kind": "file",
      "name": "openapi.yaml",
      "attrs": {
        "relpath": "docs/openapi.yaml",
        "language": "yaml",
        "role": "doc",
        "size": 194
      }
    },
    {
      "id": "file:frontend/package-lock.json",
      "kind": "file",
      "name": "package-lock.json",
      "attrs": {
        "relpath": "frontend/package-lock.json",
        "language": "json",
        "role": "lockfile",
        "size": 565
      }
    },
    {
      "id": "file:frontend/package.json",
      "kind": "file",
      "name": "package.json",
      "attrs": {
        "relpath": "frontend/package.json",
        "language": "json",
        "role": "manifest",
        "size": 173
      }
    },
    {
      "id": "file:go.mod",
      "kind": "file",
      "name": "go.mod",
      "attrs": {
        "relpath": "go.mod",
        "language": "unknown",
        "role": "manifest",
        "size": 104
      }
    },
    {
      "id": "file:requirements-extra.txt",
      "kind": "file",
      "name": "requirements-extra.txt",
      "attrs": {
        "relpath": "requirements-extra.txt",
        "language": "text",
        "role": "manifest",
        "size": 99
      }
    },
    {
      "id": "file:requirements.txt",
      "kind": "file",
      "name": "requirements.txt",
      "attrs": {
        "relpath": "requirements.txt",
        "language": "text",
        "role": "manifest",
        "size": 267
      }
    },
    {
      "id": "file:utils/__init__.py",
      "kind": "file",
      "name": "__init__.py",
      "attrs": {
        "relpath": "utils/__init__.py",
        "language": "python",
        "role": "source",
        "size": 48
      }
    },
    {
      "id": "file:utils/config_loader.py",
      "kind": "file",
      "name": "config_loader.py",
      "attrs": {
        "relpath": "utils/config_loader.py",
        "language": "python",
        "role": "source",
        "size": 313
      }
    },
    {
      "id": "fn:app.py:health",
      "kind": "function",
      "name": "health",
      "attrs": {
        "relpath": "app.py",
        "module": "app",
        "lineno": 24,
        "is_method": false
      }
    },
    {
      "id": "fn:app.py:import_data",
      "kind": "function",
      "name": "import_data",
      "attrs": {
        "relpath": "app.py",
        "module": "app",
        "lineno": 16,
        "is_method": false
      }
    },
    {
      "id": "fn:utils/config_loader.py:load_config",
      "kind": "function",
      "name": "load_config",
      "attrs": {
        "relpath": "utils/config_loader.py",
        "module": "utils.config_loader",
        "lineno": 6,
        "is_method": false
      }
    },
    {
      "id": "mod:app",
      "kind": "module",
      "name": "app",
      "attrs": {
        "relpath": "app.py",
        "docstring": "Demo application: a tiny Flask service used to exercise the scanner.\n\nIt exposes a public upload endpoint that flows user input into a configuration\nloader, plus a health check. There is nothing malic",
        "unresolved_calls": [
          "app.run"
        ],
        "unresolved_call_count": 1
      }
    },
    {
      "id": "mod:utils",
      "kind": "module",
      "name": "utils",
      "attrs": {
        "relpath": "utils/__init__.py",
        "docstring": "Utility helpers for the demo application."
      }
    },
    {
      "id": "mod:utils.config_loader",
      "kind": "module",
      "name": "utils.config_loader",
      "attrs": {
        "relpath": "utils/config_loader.py",
        "docstring": "Configuration loading helpers."
      }
    }
  ],
  "edges": [
    {
      "src": "fn:app.py:health",
      "dst": "dep:PyPI:Flask",
      "kind": "calls",
      "attrs": {
        "symbol": "flask.jsonify"
      }
    },
    {
      "src": "fn:app.py:import_data",
      "dst": "dep:PyPI:Flask",
      "kind": "calls",
      "attrs": {
        "symbol": "flask.jsonify"
      }
    },
    {
      "src": "fn:app.py:import_data",
      "dst": "dep:PyPI:Flask",
      "kind": "calls",
      "attrs": {
        "symbol": "flask.request.get_data"
      }
    },
    {
      "src": "fn:app.py:import_data",
      "dst": "fn:utils/config_loader.py:load_config",
      "kind": "calls",
      "attrs": {}
    },
    {
      "src": "fn:utils/config_loader.py:load_config",
      "dst": "dep:PyPI:PyYAML",
      "kind": "calls",
      "attrs": {
        "symbol": "yaml.load"
      }
    },
    {
      "src": "mod:app",
      "dst": "dep:PyPI:Flask",
      "kind": "calls",
      "attrs": {
        "symbol": "flask.Flask"
      }
    },
    {
      "src": "file:app.py",
      "dst": "mod:app",
      "kind": "contains",
      "attrs": {}
    },
    {
      "src": "file:utils/__init__.py",
      "dst": "mod:utils",
      "kind": "contains",
      "attrs": {}
    },
    {
      "src": "file:utils/config_loader.py",
      "dst": "mod:utils.config_loader",
      "kind": "contains",
      "attrs": {}
    },
    {
      "src": "file:composer.json",
      "dst": "dep:Packagist:guzzlehttp/guzzle",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "file:composer.json",
      "dst": "dep:Packagist:monolog/monolog",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "file:composer.json",
      "dst": "dep:Packagist:phpunit/phpunit",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "file:frontend/package.json",
      "dst": "dep:npm:lodash",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "file:frontend/package.json",
      "dst": "dep:npm:minimist",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "file:go.mod",
      "dst": "dep:Go:github.com/gin-gonic/gin",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "file:go.mod",
      "dst": "dep:Go:gopkg.in/yaml.v2",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "file:requirements-extra.txt",
      "dst": "dep:PyPI:urllib3",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "file:requirements.txt",
      "dst": "dep:PyPI:Flask",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "file:requirements.txt",
      "dst": "dep:PyPI:Jinja2",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "file:requirements.txt",
      "dst": "dep:PyPI:PyYAML",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "file:requirements.txt",
      "dst": "dep:PyPI:requests",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "file:requirements.txt",
      "dst": "dep:PyPI:urllib3",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "mod:app",
      "dst": "fn:app.py:health",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "mod:app",
      "dst": "fn:app.py:import_data",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "mod:utils.config_loader",
      "dst": "fn:utils/config_loader.py:load_config",
      "kind": "declares",
      "attrs": {}
    },
    {
      "src": "doc:README.md",
      "dst": "ep:GET:/health",
      "kind": "documents",
      "attrs": {
        "matched": "/health",
        "snippet": "_config`, which parses it as YAML. The `/health` endpoint is a simple liveness probe."
      }
    },
    {
      "src": "doc:README.md",
      "dst": "ep:POST:/import",
      "kind": "documents",
      "attrs": {
        "matched": "/import",
        "snippet": "olvable call chain. ## Endpoints The `/import` endpoint accepts uploads from any user"
      }
    },
    {
      "src": "doc:README.md",
      "dst": "fn:utils/config_loader.py:load_config",
      "kind": "documents",
      "attrs": {
        "matched": "load_config",
        "snippet": "from any user and passes the body into `load_config`, which parses it as YAML. The `/healt"
      }
    },
    {
      "src": "doc:docs/openapi.yaml",
      "dst": "ep:GET:/health",
      "kind": "documents",
      "attrs": {
        "matched": "/health",
        "snippet": "configuration from an uploaded body. /health: get: summary: Liveness probe"
      }
    },
    {
      "src": "doc:docs/openapi.yaml",
      "dst": "ep:POST:/import",
      "kind": "documents",
      "attrs": {
        "matched": "/import",
        "snippet": "tle: Demo API version: 1.0.0 paths: /import: post: summary: Import config"
      }
    },
    {
      "src": "mod:app",
      "dst": "dep:PyPI:Flask",
      "kind": "imports",
      "attrs": {}
    },
    {
      "src": "mod:app",
      "dst": "mod:utils.config_loader",
      "kind": "imports",
      "attrs": {}
    },
    {
      "src": "mod:utils.config_loader",
      "dst": "dep:PyPI:PyYAML",
      "kind": "imports",
      "attrs": {}
    },
    {
      "src": "ep:GET:/health",
      "dst": "fn:app.py:health",
      "kind": "route_to_handler",
      "attrs": {}
    },
    {
      "src": "ep:POST:/import",
      "dst": "fn:app.py:import_data",
      "kind": "route_to_handler",
      "attrs": {}
    }
  ],
  "summary": {
    "node_counts": {
      "dependency": 12,
      "doc": 2,
      "entrypoint": 2,
      "file": 11,
      "function": 3,
      "module": 3
    },
    "edge_counts": {
      "calls": 6,
      "contains": 3,
      "declares": 16,
      "documents": 5,
      "imports": 3,
      "route_to_handler": 2
    },
    "dependencies": [
      {
        "name": "github.com/gin-gonic/gin",
        "ecosystem": "Go",
        "version": "v1.6.0",
        "resolved": false,
        "source_file": "go.mod"
      },
      {
        "name": "gopkg.in/yaml.v2",
        "ecosystem": "Go",
        "version": "v2.2.2",
        "resolved": false,
        "source_file": "go.mod"
      },
      {
        "name": "guzzlehttp/guzzle",
        "ecosystem": "Packagist",
        "version": "6.3.0",
        "resolved": false,
        "source_file": "composer.json"
      },
      {
        "name": "monolog/monolog",
        "ecosystem": "Packagist",
        "version": "1.23.0",
        "resolved": false,
        "source_file": "composer.json"
      },
      {
        "name": "phpunit/phpunit",
        "ecosystem": "Packagist",
        "version": "6.5.0",
        "resolved": false,
        "source_file": "composer.json"
      },
      {
        "name": "Flask",
        "ecosystem": "PyPI",
        "version": "0.12.2",
        "resolved": false,
        "source_file": "requirements.txt"
      },
      {
        "name": "Jinja2",
        "ecosystem": "PyPI",
        "version": "2.10",
        "resolved": false,
        "source_file": "requirements.txt"
      },
      {
        "name": "PyYAML",
        "ecosystem": "PyPI",
        "version": "3.13",
        "resolved": false,
        "source_file": "requirements.txt"
      },
      {
        "name": "requests",
        "ecosystem": "PyPI",
        "version": ">=2.20.0",
        "resolved": false,
        "source_file": "requirements.txt"
      },
      {
        "name": "urllib3",
        "ecosystem": "PyPI",
        "version": "1.24.1",
        "resolved": false,
        "source_file": "requirements.txt"
      },
      {
        "name": "lodash",
        "ecosystem": "npm",
        "version": "4.17.4",
        "resolved": true,
        "source_file": "frontend/package.json"
      },
      {
        "name": "minimist",
        "ecosystem": "npm",
        "version": "1.2.0",
        "resolved": true,
        "source_file": "frontend/package.json"
      }
    ]
  }
};
