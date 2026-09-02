"""Broker falso pra testar o mycert_pkcs11 (Windows ou Mac) sem precisar do
Electron nem da conta de verdade. Serve exatamente o contrato HTTP que o
pkcs11/src/lib.rs espera de MYCERT_BROKER_URL:

  GET  /v1/certificates      -> { "certificates": [ {...CertificateWire} ] }
  POST /v1/session/login     -> { "access_token": "..." }
  GET  /v1/health            -> { "ok": true }

Uso:
  python3 mock_broker.py caminho/para/certificado.der.b64 [porta]

O arquivo passado deve conter só o der_b64 (uma linha, sem aspas nem JSON) —
o mesmo texto que você já colou no campo "Certificados em JSON" do MyCert
(recomendado: usar o mesmo der_b64 real já validado no Windows, assim o
teste no Mac compara maçã com maçã).
"""
import http.server
import json
import sys

DEFAULT_PORT = 47891


def load_der_b64() -> str:
    if len(sys.argv) < 2:
        print("Uso: python3 mock_broker.py caminho/para/der_b64.txt [porta]", file=sys.stderr)
        sys.exit(1)
    with open(sys.argv[1], "r", encoding="utf-8") as fh:
        return fh.read().strip()


DER_B64 = load_der_b64()
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT


class Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 (mantém nome exigido pela lib padrão)
        if self.path == "/v1/health":
            self._json(200, {"ok": True})
            return
        if self.path == "/v1/certificates":
            self._json(200, {
                "certificates": [{
                    "id": "cert-mock-1",
                    "alias": "MyCert QA",
                    "label": "MyCert QA",
                    "der_b64": DER_B64,
                    "public_key_der_b64": "",
                    "algorithm": "EC",
                }]
            })
            return
        self._json(404, {"message": "rota não encontrada no mock"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/v1/session/login":
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)  # não precisa validar o PIN aqui
            self._json(200, {"access_token": "mock-token-para-teste"})
            return
        self._json(404, {"message": "rota não encontrada no mock"})

    def log_message(self, format: str, *args) -> None:  # silencia log padrão
        print(f"[mock-broker] {self.address_string()} - {format % args}")


if __name__ == "__main__":
    server = http.server.HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"[mock-broker] ouvindo em http://127.0.0.1:{PORT} (Ctrl+C pra parar)")
    server.serve_forever()
