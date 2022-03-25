|            NAME            | NAMESPACE |          KIND           |       VERSION       |     REPLACEMENT      | DEPRECATED | DEPRECATED IN | REMOVED | REMOVED IN |
|----------------------------|-----------|-------------------------|---------------------|----------------------|------------|---------------|---------|------------|
| gitlab-gitaly              | default   | PodDisruptionBudget     | policy/v1beta1      | policy/v1            | true       | v1.21.0       | false   | v1.25.0    |
| gitlab-gitlab-shell        | default   | PodDisruptionBudget     | policy/v1beta1      | policy/v1            | true       | v1.21.0       | false   | v1.25.0    |
| gitlab-sidekiq-all-in-1-v1 | default   | PodDisruptionBudget     | policy/v1beta1      | policy/v1            | true       | v1.21.0       | false   | v1.25.0    |
| gitlab-webservice-default  | default   | PodDisruptionBudget     | policy/v1beta1      | policy/v1            | true       | v1.21.0       | false   | v1.25.0    |
| gitlab-minio-v1            | default   | PodDisruptionBudget     | policy/v1beta1      | policy/v1            | true       | v1.21.0       | false   | v1.25.0    |
| gitlab-registry-v1         | default   | PodDisruptionBudget     | policy/v1beta1      | policy/v1            | true       | v1.21.0       | false   | v1.25.0    |
| gitlab-gitlab-shell        | default   | HorizontalPodAutoscaler | autoscaling/v2beta1 | autoscaling/v2       | true       | v1.22.0       | false   | v1.25.0    |
| gitlab-sidekiq-all-in-1-v2 | default   | HorizontalPodAutoscaler | autoscaling/v2beta1 | autoscaling/v2       | true       | v1.22.0       | false   | v1.25.0    |
| gitlab-webservice-default  | default   | HorizontalPodAutoscaler | autoscaling/v2beta1 | autoscaling/v2       | true       | v1.22.0       | false   | v1.25.0    |
| gitlab-registry            | default   | HorizontalPodAutoscaler | autoscaling/v2beta1 | autoscaling/v2       | true       | v1.22.0       | false   | v1.25.0    |
| gitlab-webservice-default  | default   | Ingress                 | extensions/v1beta1  | networking.k8s.io/v1 | true       | v1.14.0       | true    | v1.22.0    |
| gitlab-minio               | default   | Ingress                 | extensions/v1beta1  | networking.k8s.io/v1 | true       | v1.14.0       | true    | v1.22.0    |
| gitlab-registry            | default   | Ingress                 | extensions/v1beta1  | networking.k8s.io/v1 | true       | v1.14.0       | true    | v1.22.0    |
