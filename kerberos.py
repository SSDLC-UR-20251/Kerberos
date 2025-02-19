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
        # Obtener la hora actual y calcular la expiración (5 segundos)
        now = datetime.now()
        expiration_time = now + timedelta(seconds=5)
        expiration_timestamp = expiration_time.timestamp()        

        # Crear un TGT (simulación) cifrado con la clave del AS
        tgt_data = f"{user}|{now.timestamp()}|{expiration_timestamp}|TGS".encode()
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
            user, timestamp, expiration_timestamp, realm = tgt_data.decode().split('|')

            # Convertir timestamps a valores numéricos
            expiration_timestamp = float(expiration_timestamp)
            current_time = datetime.now().timestamp()

            # Validar si el TGT ha expirado
            if current_time > expiration_timestamp:
                print(f"[TGS] El TGT de {user} ha expirado. Acceso denegado.")
                return None

            print(f"[TGS] TGT válido para {user}. Generando Service Ticket.")

            # Calcular tiempo de expiración para el Service Ticket (5 segundos)
            service_expiration_time = datetime.now() + timedelta(seconds=5)
            service_expiration_timestamp = service_expiration_time.timestamp()

            # Crear ticket de servicio
            service_ticket_data = f"{user}|{service}|{current_time}|{service_expiration_timestamp}".encode()
            service_ticket = Fernet(tgs_key).encrypt(service_ticket_data)

            print(f"[TGS] Emitiendo Service Ticket para {user} al servicio {service}. Expira en {service_expiration_time}.")
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
    
    
    def validate_service_ticket(self, service_ticket, service):
        try:
            # Descifrar el Service Ticket con la clave del TGS
            service_ticket_data = Fernet(tgs_key).decrypt(service_ticket)
            user, service_name, issue_timestamp, expiration_timestamp = service_ticket_data.decode().split('|')

            # Convertir timestamps a valores numéricos
            expiration_timestamp = float(expiration_timestamp)
            current_time = datetime.now().timestamp()

            # Validar si el ticket ha expirado
            if current_time > expiration_timestamp:
                print(f"[Cliente] El Service Ticket para {service_name} ha expirado. Acceso denegado.")
                return

            print(f"[Cliente] Acceso concedido al servicio {service_name}.")
        
        except Exception as e:
            print(f"[Cliente] Error al validar el Service Ticket: {e}")
            

    def request_service(self, tgt, tgs_server, service):
        print(f"[Cliente] Solicitando acceso al servicio {service}.")
        service_ticket = tgs_server.issue_service_ticket(tgt, service)

        if service_ticket:
            # Validar el Service Ticket antes de acceder al servicio
            self.validate_service_ticket(service_ticket, service)
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
        print("\n[Prueba] Primera solicitud al servicio:")
        service_ticket = tgs_server.issue_service_ticket(tgt, 'FileServer')
        if service_ticket:
            client.validate_service_ticket(service_ticket, 'FileServer')

        # Esperar 20 segundos para que el ticket expire
        print("\n[Prueba] Esperando 20 segundos para la expiración del Service Ticket...\n")
        time.sleep(20)

        # Intentar usar el mismo Service Ticket después de la expiración
        print("[Prueba] Segunda solicitud al servicio:")
        client.validate_service_ticket(service_ticket, 'FileServer')


# Ejecutar la simulación
if __name__ == "__main__":
    kerberos_flow()
