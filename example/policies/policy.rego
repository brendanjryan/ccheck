package main

is_hpa {
  input.kind = "HorizontalPodAutoscaler"
}

# checks that we do not include any horizontal pod autoscalers
deny[msg] {
    not is_hpa
    msg = sprintf("%s must not include any Horizontal Pod AutoScalers", [input.metadata.name])
}

# checks that apps do not live in the default namespace
warn[msg] {
    not input.metadata.namespace = "default"
    msg = sprintf("%s should not be configured to live in the default namespace", [input.metadata.name])
}
