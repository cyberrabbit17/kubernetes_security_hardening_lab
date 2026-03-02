FRONTEND=$(kubectl get pod -n production -l app=frontend \
  -o jsonpath='{.items[0].metadata.name}')

# Run all scenarios
kubectl exec -n production $FRONTEND -- sh -c "echo attacker"
kubectl exec -n production $FRONTEND -- cat /etc/passwd
kubectl exec -n production $FRONTEND -- apk --help 2>/dev/null || true

# Immediately grab alerts
sleep 3
kubectl logs -n falco -l app.kubernetes.io/name=falco --prefix \
  --since=30s | grep -E "Warning|Error|Notice|Critical" \
  | grep -v "libbpf\|TOCTOU\|tracepoint\|Log files"