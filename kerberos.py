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
        expiration_time = datetime.now() + timedelta(seconds=4)  # Expira en 4 segundos
        tgt_data = f"{user}|{time.time()}|{expiration_time.timestamp()}|TGS".encode()
        tgt = Fernet(as_key).encrypt(tgt_data)
        print(f"[AS] Emitiendo TGT para {user}. Expira en {expiration_time}.")
        return tgt

# Simulación de un Ticket Granting Server (TGS)
class TicketGrantingServer:
    def __init__(self):
        self.key = Fernet(tgs_key)

    def issue_service_ticket(self, tgt, service):
        try:
            # Descifrar el TGT con la clave del AS
            tgt_data = Fernet(as_key).decrypt(tgt)
            user, timestamp, expiration, realm = tgt_data.decode().split('|')
            
            # Validar expiración
            current_time = time.time()
            if current_time > float(expiration):
                print(f"[TGS] TGT expirado para {user}. Acceso denegado.")
                return None
            
            print(f"[TGS] TGT validado para {user}.")
            
            # Crear tiempo de expiración del Service Ticket
            service_expiration_time = datetime.now() + timedelta(seconds=5)
            service_ticket_data = f"{user}|{service}|{current_time}|{service_expiration_time.timestamp()}".encode()
            service_ticket = Fernet(tgs_key).encrypt(service_ticket_data)
            print(f"[TGS] Emitiendo ticket de servicio para {user} al servicio {service}. Expira en {service_expiration_time}.")
            return service_ticket
        except Exception as e:
            print(f"[TGS] Error al validar el TGT: {e}")
            return None
    
    def validate_service_ticket(self, service_ticket):
        try:
            # Descifrar el ticket de servicio con la clave del TGS
            service_ticket_data = Fernet(tgs_key).decrypt(service_ticket)
            user, service, timestamp, expiration = service_ticket_data.decode().split('|')
            
            # Validar expiración
            current_time = time.time()
            if current_time > float(expiration):
                print(f"[Servicio] Ticket expirado para {user}. Acceso denegado.")
                return False
            
            print(f"[Servicio] Ticket válido para {user} al servicio {service}.")
            return True
        except Exception as e:
            print(f"[Servicio] Error al validar el ticket: {e}")
            return False

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
            return service_ticket
        else:
            print(f"[Cliente] Acceso denegado al servicio {service}.")
            return None

    def access_service(self, service_ticket, tgs_server):
        print(f"[Cliente] Intentando acceder al servicio con el ticket.")
        if tgs_server.validate_service_ticket(service_ticket):
            print(f"[Cliente] Acceso exitoso al servicio.")
        else:
            print(f"[Cliente] Acceso denegado al servicio.")

# Simulación del flujo completo
def kerberos_flow():
    # Inicializar servidores
    as_server = AuthenticationServer()
    tgs_server = TicketGrantingServer()

    # Cliente solicita autenticación
    client = Client('client1')
    client2 = Client('client2')
    clients = [client, client2]
    for client in clients:
        tgt = client.request_authentication(as_server)
        if tgt:
            time.sleep(5)  # Esperar antes de solicitar el servicio (cambiar a 5 para probar expiración)
            service_ticket = client.request_service(tgt, tgs_server, 'FileServer')
            
            if service_ticket:
                time.sleep(6)  # Esperar antes de intentar acceder al servicio (cambiar a 6 para probar expiración)
                client.access_service(service_ticket, tgs_server)


# Ejecutar la simulación
if __name__ == "__main__":
    kerberos_flow()
