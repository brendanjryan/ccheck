package pkg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/brendanjryan/ccheck/pkg/parsers"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/uber-go/multierr"
)

var (
	failQ = regexp.MustCompile("deny_?[a-zA-Z]*")
	warnQ = regexp.MustCompile("warn_?[a-zA-Z]*")
)

// ConfChecker runs checks over a given set of policies and configs.
type ConfChecker struct {
	// the namespace that the rules live in:
	// https://www.openpolicyagent.org/docs/latest/how-do-i-write-policies#packages
	namespace string
	policyDir string
	configs   []string
}

func NewConfChecker(namespace string, policyDir string, configs []string) *ConfChecker {
	return &ConfChecker{
		namespace: namespace,
		policyDir: policyDir,
		configs:   configs,
	}
}

// CheckResults is a map of fileName -> results of a check operation
type CheckResults map[string]CheckResult

// CheckResult represents the results of a check operation for a single file.
type CheckResult struct {
	Failures []error
	Warnings []error
}

// Run bootstraps the ConfChecker and performs checks against all of the
// requested files.
func (c *ConfChecker) Run(ctx context.Context) (CheckResults, error) {
	// load rules from rule directory and construct an AST
	compiler := NewCompiler(c.policyDir)
	err := compiler.Build()
	if err != nil {
		return CheckResults{}, fmt.Errorf("error loading rules: %s", err)
	}

	// load configs from globs and process files to split up k8s configs
	cfs, err := c.loadConfigs(ctx, c.configs)
	if err != nil {
		return CheckResults{}, fmt.Errorf("error loading configs: %s", err)
	}

	// run files against rules defined by AST
	res := CheckResults{}
	for name, parts := range cfs {
		fs, ws, err := c.processFile(ctx, c.namespace, name, parts, compiler.Compiler)
		if err != nil {
			return CheckResults{}, fmt.Errorf("error processiong file: %s", err)
		}

		res[name] = CheckResult{
			Failures: fs,
			Warnings: ws,
		}
	}

	return res, nil
}

// loadsConfigs retrieves the config files and splits them into distinct chunks
func (c *ConfChecker) loadConfigs(ctx context.Context, files []string) (map[string][][]byte, error) {

	res := map[string][][]byte{}

	for _, f := range files {
		filePath, err := filepath.Abs(f)
		if err != nil {
			return nil, err
		}

		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("unable to open file %s: %s", f, err)
		}

		// split on k8s linebreaks if any exist
		parts := bytes.Split(data, []byte("\n---\n"))

		res[filePath] = parts
	}

	return res, nil
}

func (c *ConfChecker) processFile(ctx context.Context, namespace string, fileName string, parts [][]byte, compiler *ast.Compiler) ([]error, []error, error) {
	p, err := parsers.Get(fileName)
	if err != nil {
		return nil, nil, err
	}

	var fQueries []string
	var wQueries []string
	for _, m := range compiler.Modules {
		for _, r := range m.Rules {
			n := r.Head.Name.String()
			if warnQ.MatchString(n) {
				wQueries = append(wQueries, n)
			}
			if failQ.MatchString(n) {
				fQueries = append(fQueries, n)
			}

		}
	}

	// run checker over each "configuration part" of each file
	var fails []error
	var warns []error
	for _, part := range parts {
		var input interface{}
		err = p([]byte(part), &input)
		if err != nil {
			return nil, nil, err
		}

		for _, fq := range fQueries {
			fs := runQuery(ctx, fmt.Sprintf("data.%s.%s", namespace, fq), input, compiler)
			fails = append(fails, fs)
		}

		for _, wq := range wQueries {
			ws := runQuery(ctx, fmt.Sprintf("data.%s.%s", namespace, wq), input, compiler)
			warns = append(warns, ws)
		}
	}

	return fails, warns, nil
}

func runQuery(ctx context.Context, query string, input interface{}, compiler *ast.Compiler) error {
	hasResults := func(expression interface{}) bool {
		if v, ok := expression.([]interface{}); ok {
			return len(v) > 0
		}
		return false
	}

	rq, err := Query(query).Build(compiler, input)
	if err != nil {
		return errors.New("error constructing query : " + err.Error())
	}

	pq, err := rq.PrepareForEval(ctx)
	if err != nil {
		return errors.New("error preparing for evaluation: " + err.Error())
	}

	rr, err := pq.Eval(ctx)
	if err != nil {
		return errors.New("error evaluating rules: " + err.Error())
	}

	// extract errors from "values" of evaluation
	for _, r := range rr {
		for _, e := range r.Expressions {
			value := e.Value
			if hasResults(value) {
				for _, v := range value.([]interface{}) {
					err = multierr.Append(err, errors.New(v.(string)))
				}
			}
		}
	}

	return err
}

// Query represents a rego query.
type Query string

// Build constructs reqo query -- to run call .Eval(context.Context) on the resultant *rego.Rego struct
func (q Query) Build(compiler *ast.Compiler, in interface{}) (*rego.Rego, error) {

	opts := []func(*rego.Rego){
		rego.Query(string(q)),
		rego.Compiler(compiler),
		rego.Input(in),
	}

	return rego.New(opts...), nil
}

// Compiler is a compiled set of policies defined by *.rego files in the
// specified policy dir.
type Compiler struct {
	*ast.Compiler
	policyDir string
}

// NewCompiler instantiates a new instance of a Compiler given the policies
// defined in `policyDir`. To prepare the compiler you should run `.Build`
func NewCompiler(policyDir string) *Compiler {
	return &Compiler{
		policyDir: policyDir,
	}
}

func (c *Compiler) readPolicies(pPath string) (map[string]*ast.Module, error) {
	// double check that path exists
	info, err := os.Stat(pPath)
	if err != nil {
		return nil, fmt.Errorf("error loading policies from %s: %s", pPath, err)
	}

	files := []os.FileInfo{info}
	dirPath := filepath.Dir(pPath)

	if info.IsDir() {
		files, err = ioutil.ReadDir(pPath)
		if err != nil {
			return nil, fmt.Errorf("error loading policies from %s: %s", pPath, err)
		}
		dirPath = pPath
	}

	ms := map[string]*ast.Module{}

	for _, file := range files {
		// only consider rego files
		if !strings.HasSuffix(file.Name(), ".rego") {
			continue
		}

		// choke on being unable to read a valid .rego file
		out, err := ioutil.ReadFile(dirPath + "/" + file.Name())
		if err != nil {
			return nil, err
		}

		parsed, err := ast.ParseModule(file.Name(), string(out[:]))
		if err != nil {
			return nil, err
		}

		ms[file.Name()] = parsed
	}

	return ms, nil
}

// Build bootstraps the compiler by reading all of the supplied policy definitions.
func (c *Compiler) Build() error {
	// load policy definitions
	ps, err := c.readPolicies(c.policyDir)
	if err != nil {
		return err
	}

	a := ast.NewCompiler()
	a.Compile(ps)
	if a.Failed() {
		// check if compilation failed -- if so return errors
		return a.Errors
	}

	c.Compiler = a
	return nil
}
