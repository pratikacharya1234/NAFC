#!/bin/bash
set -e

# Install Istio CLI
curl -L https://istio.io/downloadIstio | ISTIO_VERSION=1.16.1 sh -
cd istio-1.16.1
export PATH=$PWD/bin:$PATH

# Install Istio with demo profile
istioctl install --set profile=demo -y

# Enable automatic sidecar injection for nacf namespace
kubectl label namespace nacf istio-injection=enabled --overwrite

# Install addons (Kiali, Prometheus, Grafana, Jaeger)
kubectl apply -f samples/addons
kubectl rollout status deployment/kiali -n istio-system

# Verify installation
istioctl verify-install

# Create Gateway and VirtualService for nacf
echo "Installing NACF Istio resources..."
kubectl apply -f - <<EOF
---
apiVersion: networking.istio.io/v1alpha3
kind: Gateway
metadata:
  name: nacf-gateway
  namespace: nacf
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 80
      name: http
      protocol: HTTP
    hosts:
    - "api.nacf.example.com"
    - "dashboard.nacf.example.com"
    tls:
      httpsRedirect: true
  - port:
      number: 443
      name: https
      protocol: HTTPS
    tls:
      mode: SIMPLE
      credentialName: nacf-tls
    hosts:
    - "api.nacf.example.com"
    - "dashboard.nacf.example.com"
---
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: nacf-vs
  namespace: nacf
spec:
  hosts:
  - "api.nacf.example.com"
  - "dashboard.nacf.example.com"
  gateways:
  - nacf-gateway
  http:
  - match:
    - uri:
        prefix: /auth
    route:
    - destination:
        host: auth-service.nacf.svc.cluster.local
        port:
          number: 80
  - match:
    - uri:
        prefix: /signal
    route:
    - destination:
        host: signal-processor.nacf.svc.cluster.local
        port:
          number: 80
  - match:
    - uri:
        prefix: /
    route:
    - destination:
        host: grafana.nacf.svc.cluster.local
        port:
          number: 3000
---
apiVersion: networking.istio.io/v1alpha3
kind: DestinationRule
metadata:
  name: auth-service-dr
  namespace: nacf
spec:
  host: auth-service
  trafficPolicy:
    tls:
      mode: ISTIO_MUTUAL
    loadBalancer:
      simple: LEAST_CONN
    outlierDetection:
      consecutive5xxErrors: 5
      interval: 10s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
---
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: nacf
spec:
  mtls:
    mode: STRICT
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-all
  namespace: nacf
spec:
  {}
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: auth-service-allow
  namespace: nacf
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: auth-service
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account"]
    to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/auth/*"]
---
apiVersion: telemetry.istio.io/v1alpha1
kind: Telemetry
metadata:
  name: nacf-telemetry
  namespace: nacf
spec:
  accessLogging:
  - providers:
    - name: stdout-json
  metrics:
  - providers:
    - name: prometheus
    overrides:
    - match:
        metric: REQUEST_COUNT
        mode: CLIENT_AND_SERVER
      tagOverrides:
        request_method:
          value: request.method
        response_code:
          value: response.code
        request_host:
          value: request.host
EOF

echo "Istio configuration applied successfully!"
echo "Access Kiali dashboard with: istioctl dashboard kiali"
