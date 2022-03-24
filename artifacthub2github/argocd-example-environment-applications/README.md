# argocd-example-environment-applications

Here are the ArgoCD applications for the different environments.

This application must be initially applied.

It loads the argocd-example-chart which in turn creates the App-of-Apps based on the

environment specific values in the values folder.

## Installation

```bash
kubectl apply -f [ENVIRONMENT].yaml
```

Sit back and wait.
