#!/bin/bash
# OWASP ZAP Baseline Scan
# Realiza um scan passivo de vulnerabilidades na aplicação
# Uso: ./zap/zap-baseline-scan.sh

TARGET_URL="${1:-https://serverest.dev}"
REPORT_DIR="reports"

mkdir -p "$REPORT_DIR"

echo "🔍 Iniciando OWASP ZAP Baseline Scan..."
echo "🎯 Alvo: $TARGET_URL"

docker run --rm -v "$(pwd):/zap/wrk:rw" \
  -t owasp/zap2docker-weekly \
  zap-baseline.py \
  -t "$TARGET_URL" \
  -r /zap/wrk/"$REPORT_DIR"/zap-report.html \
  -x /zap/wrk/"$REPORT_DIR"/zap-report.xml

echo ""
echo "📊 Relatório gerado: $REPORT_DIR/zap-report.html"

# Verifica vulnerabilidades de nível alto
if [ -f "$REPORT_DIR/zap-report.xml" ]; then
  if grep -q 'risk="High"' "$REPORT_DIR/zap-report.xml"; then
    echo "❌ Vulnerabilidades ALTAS encontradas! Verifique o relatório."
    grep 'risk="High"' "$REPORT_DIR/zap-report.xml" | head -5
    exit 1
  else
    echo "✅ Scan concluído sem vulnerabilidades de nível alto."
    exit 0
  fi
fi
