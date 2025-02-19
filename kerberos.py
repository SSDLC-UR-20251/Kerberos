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

# Tiempo de expiración de tickets (en segundos)
TGT_EXPIRATION = 4
SERVICE_TICKET_EXPIRATION = 5

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
        expiration_time = datetime.timestamp(datetime.now() + timedelta(seconds=TGT_EXPIRATION))  # PUNTO 1 
        tgt_data = f"{user}|{expiration_time}|TGS".encode()
        tgt = Fernet(as_key).encrypt(tgt_data)
        print(f"[AS] Emitiendo TGT para {user}, expira en {TGT_EXPIRATION} segundos.")
        return tgt

# Simulación de un Ticket Granting Server (TGS)
class TicketGrantingServer:
    def __init__(self):
        self.key = Fernet(tgs_key)

    def issue_service_ticket(self, tgt, service):
        try:
            tgt_data = Fernet(as_key).decrypt(tgt).decode()
            user, expiration_time, realm = tgt_data.split('|')
            expiration_time = float(expiration_time)
            
            # PUNTO 2 
            if time.time() > expiration_time:
                print(f"[TGS] TGT expirado para {user}. No se puede emitir ticket de servicio.")
                return None

            service_expiration_time = datetime.timestamp(datetime.now() + timedelta(seconds=SERVICE_TICKET_EXPIRATION))
            service_ticket_data = f"{user}|{service}|{service_expiration_time}".encode()
            service_ticket = Fernet(tgs_key).encrypt(service_ticket_data)
            print(f"[TGS] Emitiendo ticket de servicio para {user} al servicio {service}, expira en {SERVICE_TICKET_EXPIRATION} segundos.")
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
        return as_server.authenticate(self.name)

    def request_service(self, tgt, tgs_server, service):
        print(f"[Cliente] Solicitando acceso al servicio {service}.")
        service_ticket = tgs_server.issue_service_ticket(tgt, service)
        if service_ticket:
            # PUNTO 3 
            self.use_service(service_ticket, service) # Aqui llamamos a una Nueva Funcion implementada Para la Corroboracion del Ticket
        else:
            print(f"[Cliente] Acceso denegado al servicio {service}.")

    def use_service(self, service_ticket, service):
        try:
            service_ticket_data = Fernet(tgs_key).decrypt(service_ticket).decode()
            user, service_name, expiration_time = service_ticket_data.split('|')
            expiration_time = float(expiration_time)
            
            if time.time() > expiration_time:
                print(f"[Servicio] Ticket de servicio expirado para {user}. Acceso denegado.")
            else:
                print(f"[Servicio] {user} ha accedido correctamente a {service_name}.")
        except Exception as e:
            print(f"[Servicio] Error al validar el ticket de servicio: {e}")

# Simulación del flujo completo
def kerberos_flow():
    as_server = AuthenticationServer()
    tgs_server = TicketGrantingServer()
    client = Client('client1')
    tgt = client.request_authentication(as_server)
    
    if tgt:
        client.request_service(tgt, tgs_server, 'FileServer')
        time.sleep(6)  # Esperar para probar la expiración
        client.request_service(tgt, tgs_server, 'FileServer')

if __name__ == "__main__":
    kerberos_flow()
