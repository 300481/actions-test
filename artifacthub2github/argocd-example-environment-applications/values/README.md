# values

This folder contains the environment specific values.

## Reference

This example shows the needed settings.

```yaml
environment: dev
repos:
  argo:
    charts:
      argocd_notifications:
        enabled: true
        namespace: argocd
        syncWave: "10"
```

`environment` defines which environment specific values for each chart have to be loaded

`repos.argo.charts.argocd_notifications.enabled` enables or disables the chart

`repos.argo.charts.argocd_notifications.namespace` sets the namespace in which the chart will be installed

`repos.argo.charts.argocd_notifications.syncWave` sets the ArgoCD syncWave for the ArgoCD application which installs the chart

You have also the possibility to lock the chart version here with the `version` key.

This will override the version of the file *helm-charts.yaml*
