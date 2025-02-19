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
        # Crear un TGT (simulación) cifrado con la clave del AS
        expiration_time = (datetime.now() + timedelta(seconds=4)).timestamp()
        tgt_data = f"{user}|{time.time()}|{expiration_time}|TGS".encode()
        tgt = Fernet(as_key).encrypt(tgt_data)
        print(f"[AS] Emitiendo TGT para {user}.")
        return tgt


# Simulación de un Ticket Granting Server (TGS)
class TicketGrantingServer:
    def __init__(self):
        self.key = Fernet(tgs_key)

    def issue_service_ticket(self, tgt, service):
        try:
            # Descifrar el TGT con la clave del AS
            tgt_data = Fernet(as_key).decrypt(tgt)
            user, timestamp, expiration_time, realm = tgt_data.decode().split('|')
            current_time = time.time()
            if current_time > float(expiration_time):
                print(f"[TGS] TGT expirado para {user}.")
                return None
            print(f"[TGS] TGT validado para {user}.")

            # Emitir ticket de servicio
            service_ticket_expiration_time = (datetime.now() + timedelta(seconds=4)).timestamp()
            service_ticket_data = f"{user}|{service}|{time.time()}|{service_ticket_expiration_time}".encode()
            service_ticket = Fernet(tgs_key).encrypt(service_ticket_data)
            print(f"[TGS] Emitiendo ticket de servicio para {user} al servicio {service}.")
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
            print(f"[Cliente] Acceso concedido al servicio {service}.")
        else:
            print(f"[Cliente] Acceso denegado al servicio {service}.")
        return service_ticket

    def use_service_ticket(self, service_ticket):
        try:
            # Descifrar el Service Ticket con la clave del TGS
            service_ticket_data = Fernet(tgs_key).decrypt(service_ticket)
            user, service, timestamp, expiration_time = service_ticket_data.decode().split('|')
            current_time = time.time()
            if current_time > float(expiration_time):
                print(f"[Cliente] El ticket de servicio ha expirado para {user} al servicio {service}.")
                return False
            print(f"[Cliente] Ticket de servicio válido para {user} al servicio {service}.")
            return True
        except Exception as e:
            print(f"[Cliente] Error al validar el ticket de servicio: {e}")
            return False


# Simulación del flujo completo
def kerberos_flow():
    # Inicializar componentes
    as_server = AuthenticationServer()
    tgs_server = TicketGrantingServer()
    client = Client("Alice")

    # Cliente solicita un TGT
    tgt = as_server.issue_tgt(client.name)
    if tgt is None:
        return

    # Cliente usa el TGT para solicitar un ticket de servicio
    service_ticket = client.request_service(tgt, tgs_server, 'FileServer')
    if service_ticket is None:
        return

    # Cliente usa el ticket de servicio para acceder al servicio
    client.use_service_ticket(service_ticket)

    # Esperar 20 segundos
    time.sleep(20)

    # Cliente intenta usar el ticket de servicio nuevamente
    client.use_service_ticket(service_ticket)

# Ejecutar la simulación
if __name__ == "__main__":
    kerberos_flow()
