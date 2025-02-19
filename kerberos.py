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
        expiration_time = datetime.now() + timedelta(seconds=4)  # Expira en 4 segundos
        tgt_data = f"{user}|{time.time()}|{expiration_time.timestamp()}|TGS".encode()
        tgt = Fernet(as_key).encrypt(tgt_data)
        print(f"[AS] Emitiendo TGT para {user}, expira en {expiration_time}.")
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
            
            # Verificar si el TGT ha expirado
            if datetime.now().timestamp() > float(expiration):
                print(f"[TGS] TGT expirado para {user}. No se puede emitir un Service Ticket.")
                return None
            
            print(f"[TGS] TGT validado para {user}.")

            # Definir tiempo de expiración para el Service Ticket
            service_expiration_time = datetime.now() + timedelta(seconds=5)  # Expira en 5 segundos
            service_ticket_data = f"{user}|{service}|{time.time()}|{service_expiration_time.timestamp()}".encode()
            service_ticket = Fernet(tgs_key).encrypt(service_ticket_data)
            print(f"[TGS] Emitiendo ticket de servicio para {user} al servicio {service}, expira en {service_expiration_time}.")
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
            self.access_service(service_ticket, service)
        else:
            print(f"[Cliente] Acceso denegado al servicio {service}.")
    
    def access_service(self, service_ticket, service):
        try:
            # Descifrar el ticket de servicio con la clave del TGS
            ticket_data = Fernet(tgs_key).decrypt(service_ticket)
            user, service_name, timestamp, expiration = ticket_data.decode().split('|')
            
            # Verificar si el Service Ticket ha expirado
            if datetime.now().timestamp() > float(expiration):
                print(f"[Servicio] El ticket para {service_name} ha expirado. Acceso denegado.")
                return
            
            print(f"[Servicio] Acceso concedido a {service_name} para {user}.")
        except Exception as e:
            print(f"[Servicio] Error al validar el Service Ticket: {e}")

# Simulación del flujo completo
def kerberos_flow():
    # Inicializar servidores
    as_server = AuthenticationServer()
    tgs_server = TicketGrantingServer()

    # Cliente solicita autenticación
    client = Client('client1')
    tgt = client.request_authentication(as_server)

    if tgt:
        time.sleep(2)  # Primera solicitud antes de la expiración
        client.request_service(tgt, tgs_server, 'FileServer')
        
        time.sleep(20)  # Espera de 20 segundos para que expire el Service Ticket
        print("\n--- Realizando segunda solicitud tras la expiración del ticket ---")
        client.request_service(tgt, tgs_server, 'FileServer')

# Ejecutar la simulación
if __name__ == "__main__":
    kerberos_flow()
