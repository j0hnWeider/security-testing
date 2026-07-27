#!/bin/bash
# OWASP ZAP API Scan
# Realiza um scan ativo de vulnerabilidades na API
# Uso: ./zap/zap-api-scan.sh <URL_DA_API>

TARGET_URL="${1:-https://serverest.dev}"
REPORT_DIR="reports"

mkdir -p "$REPORT_DIR"

echo "🔍 Iniciando OWASP ZAP API Scan..."
echo "🎯 Alvo: $TARGET_URL"

docker run --rm -v "$(pwd):/zap/wrk:rw" \
  -t owasp/zap2docker-weekly \
  zap-api-scan.py \
  -t "$TARGET_URL" \
  -f openapi \
  -r /zap/wrk/"$REPORT_DIR"/zap-api-report.html

echo ""
echo "📊 Relatório gerado: $REPORT_DIR/zap-api-report.html"
