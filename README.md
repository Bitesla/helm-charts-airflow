<h1 align="center">Airflow Helm Chart (User Community)</h1>

<p align="center">
  The <code>User-Community Airflow Helm Chart</code> is the standard way to deploy <a href="https://airflow.apache.org/">Apache Airflow</a> on <a href="https://kubernetes.io/">Kubernetes</a> with <a href="https://helm.sh/">Helm</a>.
  Originally created in 2017, it has since helped thousands of companies create production-ready deployments of Airflow on Kubernetes.
</p>

<p align="center">
  <a href="https://github.com/airflow-helm/charts/releases">
    <img alt="Downloads" src="https://img.shields.io/github/downloads/airflow-helm/charts/total?style=flat-square&color=28a745">
  </a>
  <a href="https://github.com/airflow-helm/charts/graphs/contributors">
    <img alt="Contributors" src="https://img.shields.io/github/contributors/airflow-helm/charts?style=flat-square&color=28a745">
  </a>
  <a href="https://github.com/airflow-helm/charts/blob/main/LICENSE">
    <img alt="License" src="https://img.shields.io/github/license/airflow-helm/charts?style=flat-square&color=28a745">
  </a>
  <a href="https://github.com/airflow-helm/charts/releases">
    <img alt="Latest Release" src="https://img.shields.io/github/v/release/airflow-helm/charts?style=flat-square&color=6f42c1&label=latest%20release">
  </a>
  <a href="https://artifacthub.io/packages/helm/airflow-helm/airflow">
    <img alt="ArtifactHub" src="https://img.shields.io/static/v1?style=flat-square&color=417598&logo=artifacthub&label=ArtifactHub&message=airflow-helm">
  </a>
</p>

<p align="center">
  <a href="https://github.com/airflow-helm/charts/stargazers">
    <img alt="GitHub Stars" src="https://img.shields.io/github/stars/airflow-helm/charts?style=for-the-badge&color=ffcb2f&label=Support%20with%20%E2%AD%90%20on%20GitHub">
  </a>
  <a href="https://artifacthub.io/packages/helm/airflow-helm/airflow">
    <img alt="ArtifactHub Stars" src="https://img.shields.io/badge/dynamic/json?style=for-the-badge&color=ffcb2f&label=Support%20with%20%E2%AD%90%20on%20ArtifactHub&query=stars&url=https://artifacthub.io/api/v1/packages/af52c9e8-afa6-4443-952f-3d4d17e3be35/stars">
  </a>
</p>

<p align="center">
  <a href="https://github.com/airflow-helm/charts/discussions">
    <img alt="GitHub Discussions" src="https://img.shields.io/github/discussions/airflow-helm/charts?style=for-the-badge&color=17a2b8&label=Start%20a%20Discussion">
  </a>
  <a href="https://github.com/airflow-helm/charts/issues/new/choose">
    <img alt="GitHub Issues" src="https://img.shields.io/github/issues/airflow-helm/charts?style=for-the-badge&color=17a2b8&label=Open%20an%20Issue">
  </a>
</p>

<h3 align="center">↓ ↓ ↓</h3>

<h1 align="center"><a href="https://github.com/airflow-helm/charts/tree/main/charts/airflow">Chart Homepage</a></h1>



NAME: airflow-cluster
LAST DEPLOYED: Mon Jun 17 12:59:31 2024
NAMESPACE: airflow-cluster
STATUS: deployed
REVISION: 1
TEST SUITE: None
NOTES:
========================================================================
Thanks for deploying Apache Airflow with the User-Community Helm Chart!

====================
        TIPS
====================

You have NOT set up persistence for worker task logs, do this by:
  1. Using a PersistentVolumeClaim with `logs.persistence.*`
  2. Using remote logging with `AIRFLOW__LOGGING__REMOTE_LOGGING`

It looks like you have NOT exposed the Airflow Webserver, do this by:
  1. Using a Kubernetes Ingress with `ingress.*`
  2. Using a Kubernetes LoadBalancer/NodePort type Service with `web.service.type`

Use these commands to port-forward the Services to your localhost:
  * Airflow Webserver:  kubectl port-forward svc/airflow-cluster-web 8080:8080 --namespace airflow-cluster
  * Flower Dashboard:   kubectl port-forward svc/airflow-cluster-flower 5555:5555 --namespace airflow-cluster

====================
      WARNINGS
====================
[HIGH] using the embedded postgres database is NOT suitable for production!
  * HELP: use an external postgres/mysql database with `externalDatabase.*`

[MEDIUM] the scheduler "task creation check" is disabled, the scheduler may not be restarted if it deadlocks!
  * HELP: configure the check with `scheduler.livenessProbe.taskCreationCheck.*`

========================================================================