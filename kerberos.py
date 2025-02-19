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

# Tiempo de expiración
delta = 5  # Expiración del TGT en segundos
service_ticket_expiry = 10  # Expiración del Service Ticket en segundos

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
        # Crear un TGT con expiración (en segundos)
        now = datetime.now()
        expiration_time = now + timedelta(seconds=delta)  # Tiempo de expiración del TGT
        t_emi = time.time()  # Establecer el tiempo de emisión
        tgt_data = f"{user}|{t_emi}|{expiration_time}".encode()  # Agregar la fecha de expiración
        tgt = Fernet(as_key).encrypt(tgt_data)
        print(f"[AS] Emitiendo TGT para {user}, con expiración a las {expiration_time}.")
        return tgt, expiration_time  # Devolver TGT y la fecha de expiración


# Simulación de un Ticket Granting Server (TGS)
class TicketGrantingServer:
    def __init__(self):
        self.key = Fernet(tgs_key)

    def issue_service_ticket(self, tgt, service, expiration_time):
        try:
            t_t = time.time()
            # Verificar si el TGT ha expirado
            if t_t > expiration_time.timestamp():
                print(f"[TGS] Error, el TGT ya expiró a las {expiration_time}.")
                return None 
            # Descifrar el TGT con la clave del AS
            tgt_data = Fernet(as_key).decrypt(tgt)
            user, timestamp, realm = tgt_data.decode().split('|')
            print(f"[TGS] TGT validado para {user}.")

            # Calcular la expiración del Service Ticket
            service_ticket_emi = time.time()  # Tiempo de emisión del Service Ticket
            service_ticket_exp = service_ticket_emi + service_ticket_expiry  # Expiración en segundos
            service_ticket_data = f"{user}|{service}|{service_ticket_emi}|{service_ticket_exp}".encode()

            # Emitir el ticket de servicio
            service_ticket = Fernet(tgs_key).encrypt(service_ticket_data)
            print(f"[TGS] Emitiendo ticket de servicio para {user} al servicio {service}.")
            return service_ticket, service_ticket_exp
        except Exception as e:
            print(f"[TGS] Error al validar el TGT: {e}")
            return None


# Simulación del cliente que interactúa con AS y TGS
class Client:
    def __init__(self, name):
        self.name = name

    def request_authentication(self, as_server):
        print(f"[Cliente] Solicitando autenticación para {self.name}.")
        tgt, expiration_time = as_server.authenticate(self.name)
        return tgt, expiration_time

    def request_service(self, tgt, expiration_time, tgs_server, service):
        print(f"[Cliente] Solicitando acceso al servicio {service}.")
        service_ticket, service_ticket_exp = tgs_server.issue_service_ticket(tgt, service, expiration_time)
        t_t = time.time()
        if t_t > service_ticket_exp:
            print(f"[Cliente] El ticket ha expirado.")
            service_ticket = None
        if service_ticket:
            print(f"[Cliente] Acceso concedido al servicio {service}.")
        else:
            print(f"[Cliente] Acceso denegado al servicio {service}.")


# Simulación del flujo completo
def kerberos_flow():
    # Inicializar servidores
    as_server = AuthenticationServer()
    tgs_server = TicketGrantingServer()

    # Cliente solicita autenticación
    client = Client('client1')
    tgt, expiration_time = client.request_authentication(as_server)

    if tgt:
        # Cliente usa el TGT para solicitar un ticket de servicio
        client.request_service(tgt, expiration_time, tgs_server, 'FileServer')


# Ejecutar la simulación
if __name__ == "__main__":
    kerberos_flow()
