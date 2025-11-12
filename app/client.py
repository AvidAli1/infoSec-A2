"""Client skeleton — plain TCP; no TLS. See assignment spec."""

# def main():
#     raise NotImplementedError("students: implement client workflow")

# if __name__ == "__main__":
#     main()

# certificate validation
from app.crypto.pki import validate_server_certificate
# diffie hellman key exchange
from app.crypto.dh import client_dh_initiate, client_dh_finalize

#----------------------------------------------------------------------
# Example usage of certificate validation
#----------------------------------------------------------------------
# ca.pem is bundled with your client
CA_PATH = "certs/MyRootCA_ca_cert.pem"
EXPECTED_SERVER = "myserver.example.com"

server_cert = validate_server_certificate(
    server_hello_msg["server cert"],
    CA_PATH,
    EXPECTED_SERVER
)

#----------------------------------------------------------------------
# Example usage of DH key exchange
#----------------------------------------------------------------------
# After auth
client_priv, dh_msg = client_dh_initiate()
send_json(dh_msg)

# Receive server response
server_resp = recv_json()
aes_key = client_dh_finalize(client_priv, server_resp)
