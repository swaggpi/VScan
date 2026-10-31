"""Tests for the Go adapter of the sound taint pass.

Everything here is OFFLINE and deterministic: taint is a pure static analysis
over re-parsed source on proven reachability paths -- no network, no model, no
``go mod download`` (the dependency node, the ``calls`` edge and the resolved
symbol all come from the analyzer offline).

Coverage:
* end-to-end positive on the real fixture (``samples/go-taint-app``: the
  ``c.PostForm -> yaml.Unmarshal`` flow), and its toml negatives;
* soundness NEGATIVES as tiny throwaway repos (no sink, rebind-to-constant,
  constant-only, call-return laundering, variadic decline, struct-field write,
  cross-package name collision, both-branch kill);
* soundness POSITIVES across the source families (net/http FormValue, body
  reader io.ReadAll, gin ShouldBindJSON, echo QueryParam/Bind, gorilla mux.Vars,
  fmt.Sprintf, single-branch kill, cross-package flow);
* a guard that the Python and JavaScript suites are unaffected.
"""

from __future__ import annotations

import os
import textwrap

from scanner.reachability import compute_reachability
from scanner.scan import scan_repo
from scanner.taint import NOT_PROVEN, TAINTED, compute_taint

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GO_TAINT_APP = os.path.join(REPO, "samples", "go-taint-app")

_YAML = "dep:Go:gopkg.in/yaml.v2"
_TOML = "dep:Go:github.com/BurntSushi/toml"

_GO_MOD = """\
module example.com/app

go 1.19

require (
	github.com/BurntSushi/toml v1.2.1
	github.com/gin-gonic/gin v1.6.0
	github.com/gorilla/mux v1.8.0
	github.com/labstack/echo v3.3.10
	gopkg.in/yaml.v2 v2.2.2
)
"""

# A gin app whose ``sink([]byte)`` is the yaml dependency sink, plus two decoy
# callees. ``{handler}`` is substituted with each test's handler.
_GIN_APP = """\
package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Name string
}

func sink(cfg []byte) {
	var c Config
	yaml.Unmarshal(cfg, &c)
}

func vsink(parts ...[]byte) {
	for _, p := range parts {
		var c Config
		yaml.Unmarshal(p, &c)
	}
}

func launder(s string) string {
	return s
}

var _ = fmt.Sprintf

{handler}

func main() {
	r := gin.Default()
	r.POST("/x", handler)
	_ = r
}
"""

# A net/http app whose ``sink([]byte)`` is the yaml sink.
_HTTP_APP = """\
package main

import (
	"io"
	"net/http"

	"gopkg.in/yaml.v2"
)

type Config struct {
	Name string
}

func sink(cfg []byte) {
	var c Config
	yaml.Unmarshal(cfg, &c)
}

{handler}

func main() {
	http.HandleFunc("/x", handler)
	_ = http.ListenAndServe
}
"""


def _write_repo(tmp_path, files: dict[str, str]) -> str:
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    return str(tmp_path)


def _taint_for(path: str):
    graph = scan_repo(path)
    reach = compute_reachability(graph)
    return compute_taint(graph, reach, os.path.abspath(path))


def _gin_yaml_verdict(tmp_path, handler: str) -> str:
    repo = _write_repo(
        tmp_path,
        {
            "go.mod": _GO_MOD,
            "main.go": _GIN_APP.replace("{handler}", textwrap.dedent(handler)),
        },
    )
    return _taint_for(repo)[_YAML].verdict


def _http_yaml_verdict(tmp_path, handler: str) -> str:
    repo = _write_repo(
        tmp_path,
        {
            "go.mod": _GO_MOD,
            "main.go": _HTTP_APP.replace("{handler}", textwrap.dedent(handler)),
        },
    )
    return _taint_for(repo)[_YAML].verdict


# -- end-to-end on the real fixture -------------------------------------------


def test_go_taint_app_yaml_is_tainted():
    result = _taint_for(GO_TAINT_APP)[_YAML]
    assert result.verdict == TAINTED
    assert result.source == "c.PostForm"
    assert result.sink_symbol == "yaml.Unmarshal"
    assert result.entrypoint == "POST /import"
    assert result.path == [
        "ep:POST:/import",
        "fn:main.go:importHandler",
        "fn:main.go:parseYAML",
        "dep:Go:gopkg.in/yaml.v2",
    ]


def test_go_taint_app_toml_is_not_proven():
    # toml is reached only by the rebind-to-constant and constant-only routes.
    assert _taint_for(GO_TAINT_APP)[_TOML].verdict == NOT_PROVEN


# -- soundness negatives ------------------------------------------------------


def test_no_source_passed_is_not_proven(tmp_path):
    # Reads a request source but passes only a constant to the sink.
    verdict = _gin_yaml_verdict(
        tmp_path,
        """
        func handler(c *gin.Context) {
          q := c.Query("term")
          _ = q
          sink([]byte("ro"))
        }
        """,
    )
    assert verdict == NOT_PROVEN


def test_rebind_to_constant_is_not_proven(tmp_path):
    verdict = _gin_yaml_verdict(
        tmp_path,
        """
        func handler(c *gin.Context) {
          data := c.PostForm("data")
          data = "safe"
          sink([]byte(data))
        }
        """,
    )
    assert verdict == NOT_PROVEN


def test_constant_only_sink_is_not_proven(tmp_path):
    verdict = _gin_yaml_verdict(
        tmp_path,
        """
        func handler(c *gin.Context) {
          sink([]byte("ro"))
        }
        """,
    )
    assert verdict == NOT_PROVEN


def test_call_return_laundering_is_not_proven(tmp_path):
    # A generic call's return value is never tainted (launder here).
    verdict = _gin_yaml_verdict(
        tmp_path,
        """
        func handler(c *gin.Context) {
          data := launder(c.PostForm("data"))
          sink([]byte(data))
        }
        """,
    )
    assert verdict == NOT_PROVEN


def test_variadic_callee_is_not_bound(tmp_path):
    # A variadic callee parameter declines the arg->param binding (conservative).
    verdict = _gin_yaml_verdict(
        tmp_path,
        """
        func handler(c *gin.Context) {
          data := c.PostForm("data")
          vsink([]byte(data))
        }
        """,
    )
    assert verdict == NOT_PROVEN


def test_if_else_both_overwrite_is_not_proven(tmp_path):
    # Both arms kill the tainted name -> the may-JOIN removes it (every path
    # kills) -> not proven.
    verdict = _gin_yaml_verdict(
        tmp_path,
        """
        func handler(c *gin.Context) {
          data := c.PostForm("data")
          if c.Query("f") != "" {
            data = "a"
          } else {
            data = "b"
          }
          sink([]byte(data))
        }
        """,
    )
    assert verdict == NOT_PROVEN


def test_comma_ok_presence_bool_is_not_proven(tmp_path):
    # ``_, ok := m[k]`` binds a presence BOOL, never attacker data. The tuple
    # bind must taint only the value position (index 0) and kill the rest, so the
    # ``ok`` flowing to the sink is not proven tainted (comma-ok over-taint bug).
    verdict = _http_yaml_verdict(
        tmp_path,
        """
        func handler(w http.ResponseWriter, r *http.Request) {
          m := r.Form
          _, ok := m["id"]
          sink([]byte(ok))
        }
        """,
    )
    assert verdict == NOT_PROVEN


def test_struct_field_write_does_not_taint_struct(tmp_path):
    # Writing a tainted value into a struct field does not taint the struct.
    repo = _write_repo(
        tmp_path,
        {
            "go.mod": _GO_MOD,
            "main.go": """
                package main

                import (
                	"github.com/gin-gonic/gin"
                	"gopkg.in/yaml.v2"
                )

                type Config struct{ Name string }
                type Wrap struct{ Data []byte }

                func handler(c *gin.Context) {
                	var w Wrap
                	w.Data = []byte(c.PostForm("data"))
                	sink2(w)
                }

                func sink2(w Wrap) {
                	var cfg Config
                	yaml.Unmarshal(w.Data, &cfg)
                }

                func main() {
                	r := gin.Default()
                	r.POST("/x", handler)
                	_ = r
                }
                """,
        },
    )
    assert _taint_for(repo)[_YAML].verdict == NOT_PROVEN


def test_cross_package_name_collision_does_not_leak(tmp_path):
    # The on-path sink caller is the CROSS-PACKAGE export ``store.Load``; a decoy
    # local ``Load`` with the SAME simple name carries the attacker value. Binding
    # by bare name would leak ``c.Query`` into ``store.Load``'s parameter. The
    # adapter binds only from the call the analyzer resolves to the on-path fn id
    # (the cross-package ``store.Load("safe")`` with a CONSTANT), so no leak.
    repo = _write_repo(
        tmp_path,
        {
            "go.mod": _GO_MOD,
            "main.go": """
                package main

                import (
                	"github.com/gin-gonic/gin"
                	"example.com/app/store"
                )

                // Decoy: a local fn sharing the export's simple name, fed evil.
                func Load(s string) {}

                func handler(c *gin.Context) {
                	evil := c.Query("q")
                	Load(evil)             // resolves to LOCAL Load -> off path
                	store.Load("safe")     // on-path sink caller, CONSTANT
                }

                func main() {
                	r := gin.Default()
                	r.POST("/x", handler)
                	_ = r
                }
                """,
            "store/store.go": """
                package store

                import "gopkg.in/yaml.v2"

                type Config struct{ Name string }

                func Load(cfg string) {
                	var c Config
                	yaml.Unmarshal([]byte(cfg), &c)
                }
                """,
        },
    )
    assert _taint_for(repo)[_YAML].verdict == NOT_PROVEN


# -- soundness positives ------------------------------------------------------


def test_positive_direct_flow_is_tainted(tmp_path):
    verdict = _gin_yaml_verdict(
        tmp_path,
        """
        func handler(c *gin.Context) {
          sink([]byte(c.PostForm("data")))
        }
        """,
    )
    assert verdict == TAINTED


def test_single_branch_kill_stays_tainted(tmp_path):
    # Only one arm kills; the implicit-else path keeps the attacker value.
    verdict = _gin_yaml_verdict(
        tmp_path,
        """
        func handler(c *gin.Context) {
          data := c.PostForm("data")
          if c.Query("f") != "" {
            data = "safe"
          }
          sink([]byte(data))
        }
        """,
    )
    assert verdict == TAINTED


def test_sprintf_flow_is_tainted(tmp_path):
    verdict = _gin_yaml_verdict(
        tmp_path,
        """
        func handler(c *gin.Context) {
          s := fmt.Sprintf("name: %s", c.PostForm("data"))
          sink([]byte(s))
        }
        """,
    )
    assert verdict == TAINTED


def test_gin_should_bind_json_taints_target(tmp_path):
    repo = _write_repo(
        tmp_path,
        {
            "go.mod": _GO_MOD,
            "main.go": """
                package main

                import (
                	"github.com/gin-gonic/gin"
                	"gopkg.in/yaml.v2"
                )

                type Config struct{ Name string }

                func handler(c *gin.Context) {
                	var body []byte
                	c.ShouldBindJSON(&body)
                	sink(body)
                }

                func sink(cfg []byte) {
                	var c Config
                	yaml.Unmarshal(cfg, &c)
                }

                func main() {
                	r := gin.Default()
                	r.POST("/x", handler)
                	_ = r
                }
                """,
        },
    )
    assert _taint_for(repo)[_YAML].verdict == TAINTED


def test_http_form_value_is_tainted(tmp_path):
    verdict = _http_yaml_verdict(
        tmp_path,
        """
        func handler(w http.ResponseWriter, r *http.Request) {
          data := r.FormValue("data")
          sink([]byte(data))
        }
        """,
    )
    assert verdict == TAINTED


def test_http_body_reader_tuple_source_is_tainted(tmp_path):
    # ``data, err := io.ReadAll(r.Body)`` taints the DATA position only.
    verdict = _http_yaml_verdict(
        tmp_path,
        """
        func handler(w http.ResponseWriter, r *http.Request) {
          data, err := io.ReadAll(r.Body)
          _ = err
          sink(data)
        }
        """,
    )
    assert verdict == TAINTED


def test_http_url_query_getter_is_tainted(tmp_path):
    verdict = _http_yaml_verdict(
        tmp_path,
        """
        func handler(w http.ResponseWriter, r *http.Request) {
          v := r.URL.Query().Get("data")
          sink([]byte(v))
        }
        """,
    )
    assert verdict == TAINTED


def test_mux_vars_is_tainted(tmp_path):
    repo = _write_repo(
        tmp_path,
        {
            "go.mod": _GO_MOD,
            "main.go": """
                package main

                import (
                	"net/http"

                	"github.com/gorilla/mux"
                	"gopkg.in/yaml.v2"
                )

                type Config struct{ Name string }

                func handler(w http.ResponseWriter, r *http.Request) {
                	vars := mux.Vars(r)
                	id := vars["id"]
                	sink([]byte(id))
                }

                func sink(cfg []byte) {
                	var c Config
                	yaml.Unmarshal(cfg, &c)
                }

                func main() {
                	http.HandleFunc("/x", handler)
                	_ = http.ListenAndServe
                }
                """,
        },
    )
    assert _taint_for(repo)[_YAML].verdict == TAINTED


def test_echo_query_param_is_tainted(tmp_path):
    repo = _write_repo(
        tmp_path,
        {
            "go.mod": _GO_MOD,
            "main.go": """
                package main

                import (
                	"github.com/labstack/echo"
                	"gopkg.in/yaml.v2"
                )

                type Config struct{ Name string }

                func handler(c echo.Context) error {
                	data := c.QueryParam("data")
                	sink([]byte(data))
                	return nil
                }

                func sink(cfg []byte) {
                	var c Config
                	yaml.Unmarshal(cfg, &c)
                }

                func main() {
                	e := echo.New()
                	e.GET("/x", handler)
                	_ = e
                }
                """,
        },
    )
    assert _taint_for(repo)[_YAML].verdict == TAINTED


def test_cross_package_flow_is_tainted(tmp_path):
    # Mirror of the name-collision negative but feeding store.Load the attacker
    # value -- proving the negative is the pass refusing, not the wiring failing.
    repo = _write_repo(
        tmp_path,
        {
            "go.mod": _GO_MOD,
            "main.go": """
                package main

                import (
                	"github.com/gin-gonic/gin"
                	"example.com/app/store"
                )

                func handler(c *gin.Context) {
                	evil := c.Query("q")
                	store.Load(evil)
                }

                func main() {
                	r := gin.Default()
                	r.POST("/x", handler)
                	_ = r
                }
                """,
            "store/store.go": """
                package store

                import "gopkg.in/yaml.v2"

                type Config struct{ Name string }

                func Load(cfg string) {
                	var c Config
                	yaml.Unmarshal([]byte(cfg), &c)
                }
                """,
        },
    )
    result = _taint_for(repo)[_YAML]
    assert result.verdict == TAINTED
    assert result.source == "c.Query"
    assert result.sink_symbol == "yaml.Unmarshal"


# -- the Go adapter does not disturb the Python / JavaScript passes -----------


def test_python_fixture_still_tainted_through_registry():
    vuln = os.path.join(REPO, "samples", "vulnerable-app")
    result = _taint_for(vuln)["dep:PyPI:PyYAML"]
    assert result.verdict == TAINTED
    assert result.source == "request.get_data"
    assert result.sink_symbol == "yaml.load"


def test_js_fixture_still_tainted_through_registry():
    js = os.path.join(REPO, "samples", "js-taint-app")
    result = _taint_for(js)["dep:npm:lodash"]
    assert result.verdict == TAINTED
    assert result.source == "req.body"
    assert result.sink_symbol == "lodash.merge"
