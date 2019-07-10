# `ccheck`
---

`ccheck` is a command line application for writing tests against configuration files and data using the [`rego` query language](https://www.openpolicyagent.org/docs/latest). It was primarily written for checking Kubernetes config files, but is generic enough to be used for any "structured" data format.

## Usage

The `ccheck` binary checks for `rego` rules of the form `deny_<rule_name>` and `warn_<rule_name>` during its evaluation process. If a resource matches a `"deny"` rule, a failure will be issued, otherwise a `"warning"` will be logged to the command line. An example of a valid, well-formed `ccheck` config is as follows:

**Example `.rego file`**

```rego
package main

is_hpa {
  input.kind = "HorizontalPodAutoscaler"
}

# checks that we do not include any horizontal pod autoscalers
deny_no_hpa[msg] {
    not is_hpa
    msg = sprintf("%s must not include any Horizontal Pod AutoScalers", [input.metadata.name])
}

# checks that apps do not live in the default namespace
warn_no_default_namespace[msg] {
    not input.metadata.namespace = "default"
    msg = sprintf("%s should not be configured to live in the default namespace", [input.metadata.name])
```

**N.B.** As an added bonus you can also use `ccheck` rules as policies in the [Open Policy Agent Admission Controller](https://www.openpolicyagent.org/docs/latest/kubernetes-admission-control/#4-define-a-policy-and-load-it-into-opa-via-kubernetes) 

`ccheck` can then be invoked using this policy via: 

```bash 
ccheck -p <policy directory> <files to check....>
```

For example using the following file:

**Example Kubernetes `.yaml` file**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.7.9
        ports:
        - containerPort: 80

---

apiVersion: autoscaling/v1
kind: HorizontalPodAutoscaler
metadata:
  name: nginx
  namespace: default
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: nginx
  minReplicas: 1
  maxReplicas: 10
  targetCPUUtilizationPercentage: 50
```

Will produce the following output: 

```bash 
Warning: /Users/brendanjryan/projects/ccheck/example/test.yaml - nginx-deployment should not be configured to live in the default namespace
Failure: /Users/brendanjryan/projects/ccheck/example/test.yaml - nginx-deployment must not include any Horizontal Pod AutoScalers
brendanjryan@Brendans-MacBook-Pro:~/projects/ccheck|
```


**Full Example:**

If you would like to see `ccheck` in action - this project bundles this example in its source as well. Just `clone` this project and run: 


```bash
./ccheck -p example/policies example/test.yaml 
Warning: /Users/brendanjryan/projects/ccheck/example/test.yaml - nginx-deployment should not be configured to live in the default namespace
Failure: /Users/brendanjryan/projects/ccheck/example/test.yaml - nginx-deployment must not include any Horizontal Pod AutoScalers
```

## FAQ

- Why use `rego` instead of another declarative language like `hcl`?

  Although `rego` is a very new and domain specific language, it's simple grammar and extensibility were the main motivators in using it instead of a more popular declarative language or framework. As an added bonus, you can re-use your policies declared in `rego` right out of the box in [kubernetes admission controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/) powered by [Open Policy Agent](https://www.openpolicyagent.org/)

## Additional References

- [Rego language spec](https://www.openpolicyagent.org/docs/latest)
- [Open Policy Agent Project](https://www.openpolicyagent.org/)
