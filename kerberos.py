from cryptography.fernet import Fernet
import time
from datetime import datetime, timedelta

# Simulación de base de datos de usuarios y claves
users_db = {
    'client1': Fernet.generate_key(),
    'client2': Fernet.generate_key(),
}

# Servidores AS y TGS con claves compartidas
as_key = Fernet.generate_key()  # Clave del Authentication Server
tgs_key = Fernet.generate_key()  # Clave del Ticket Granting Server


# Simulación de un Authentication Server (AS)
class AuthenticationServer:
    def __init__(self):
        self.key = Fernet(as_key)

    def authenticate(self, user):
        if user in users_db:
            print(f"[AS] Usuario {user} autenticado.")
            return self.issue_tgt(user)
        else:
            print(f"[AS] Autenticación fallida para el usuario {user}.")
            return None

    def issue_tgt(self, user):
        expiration_time = datetime.now() + timedelta(seconds=5)
        # Guardamos el tiempo de expiración como un timestamp
        expiration_timestamp = expiration_time.timestamp()
        tgt_data = f"{user}|{time.time()}|{expiration_timestamp}|TGS".encode()
        tgt = Fernet(as_key).encrypt(tgt_data)
        print(f"[AS] Emitiendo TGT para {user}. Expira en: {expiration_time}")
        return tgt


# Simulación de un Ticket Granting Server (TGS)
class TicketGrantingServer:
    def __init__(self):
        self.key = Fernet(tgs_key)

    def issue_service_ticket(self, tgt, service):
        try:
            # Descifrar el TGT con la clave del AS
            tgt_data = Fernet(as_key).decrypt(tgt)
            user, timestamp, expiration_timestamp, realm = tgt_data.decode().split('|')
            expiration_time = datetime.fromtimestamp(float(expiration_timestamp))

            if datetime.now() > expiration_time:
                print(f"[TGS] El TGT para {user} ha expirado.")
                return None

            print(f"[TGS] TGT validado para {user}. Expira en: {expiration_time}")

            # Emitir ticket de servicio con tiempo de expiración
            service_expiration_time = datetime.now() + timedelta(seconds=5)
            service_expiration_timestamp = service_expiration_time.timestamp()
            service_ticket_data = f"{user}|{service}|{time.time()}|{service_expiration_timestamp}".encode()
            service_ticket = Fernet(tgs_key).encrypt(service_ticket_data)
            print(f"[TGS] Emitiendo ticket de servicio para {user} al servicio {service}. Expira en: {service_expiration_time}")
            return service_ticket
        except Exception as e:
            print(f"[TGS] Error al validar el TGT: {e}")
            return None


# Simulación del cliente que interactúa con AS y TGS
class Client:
    def __init__(self, name):
        self.name = name

    def request_authentication(self, as_server):
        print(f"[Cliente] Solicitando autenticación para {self.name}.")
        tgt = as_server.authenticate(self.name)
        return tgt

    def request_service(self, tgt, tgs_server, service):
        print(f"[Cliente] Solicitando acceso al servicio {service}.")
        service_ticket = tgs_server.issue_service_ticket(tgt, service)

        if service_ticket:
            # Verificación del Service Ticket
            service_data = Fernet(tgs_key).decrypt(service_ticket)
            user, service, timestamp, expiration_timestamp = service_data.decode().split('|')
            expiration_time = datetime.fromtimestamp(float(expiration_timestamp))  # Asegúrate de convertir el string a float

            if datetime.now() > expiration_time:
                print(f"[Cliente] El Service Ticket ha expirado para {user}. Acceso denegado.")
                return None

            print(f"[Cliente] El Service Ticket es válido para {user}. Acceso concedido.")
        else:
            print(f"[Cliente] Acceso denegado al servicio {service}.")


# Simulación del flujo completo
def kerberos_flow():
    # Inicializar servidores
    as_server = AuthenticationServer()
    tgs_server = TicketGrantingServer()

    # Cliente solicita autenticación
    client = Client('client1')
    tgt = client.request_authentication(as_server)

    if tgt:
        # Cliente usa el TGT para solicitar un ticket de servicio
        client.request_service(tgt, tgs_server, 'FileServer')

    time.sleep(10)  
    print("\n[Cliente] Intentando realizar una segunda solicitud despues de 10 segundos.")
    client.request_service(tgt, tgs_server, 'FileServer')


# Ejecutar la simulación
if __name__ == "__main__":
    kerberos_flow()
