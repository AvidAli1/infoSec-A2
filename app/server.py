"""Server skeleton — plain TCP; no TLS. See assignment spec."""

# def main():
#     raise NotImplementedError("students: implement server workflow")

# if __name__ == "__main__":
#     main()

# certificate validation 
from app.crypto.pki import validate_client_certificate
# diffie hellman key exchange
from app.crypto.dh import generate_dh_pair, server_dh_respond

#----------------------------------------------------------------------
# Example usage of certificate validation
#----------------------------------------------------------------------
CA_PATH = "certs/MyRootCA_ca_cert.pem"

client_cert = validate_client_certificate(
    client_hello_msg["client cert"],
    CA_PATH
    # Optionally pass expected CN if you enforce it
)

#----------------------------------------------------------------------
# Example usage of DH key exchange
#----------------------------------------------------------------------
# After receiving dh client
server_priv, _ = generate_dh_pair()
aes_key, resp_msg = server_dh_respond(client_dh_msg, server_priv)
send_json(resp_msg)