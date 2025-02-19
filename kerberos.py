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
       # Crear un TGT con tiempo de expiración (3 segundos a partir de ahora)
        expiration_time = (datetime.now() + timedelta(seconds=3)).strftime("%Y-%m-%d %H:%M:%S")  # Hora local
        tgt_data = f"{user}|{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}|{expiration_time}|TGS".encode()
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
            user, timestamp, expiration_time, realm = tgt_data.decode().split('|')
            print(f"[TGS] Validando TGT para {user} ")
            # Verificar si el TGT ha expirado comparando las horas
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if current_time > expiration_time:
                print(f"[TGS] El TGT ha expirado para {user}. Acceso denegado. Hora actual: {current_time}")
                return None
            else:
                print(f"[TGS] TGT validado para {user}. Hora actual: {current_time}")
                # Emitir ticket de servicio con un nuevo tiempo de expiración
                service_ticket_data = f"{user}|{service}|{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}|{(datetime.now() + timedelta(seconds=3)).strftime('%Y-%m-%d %H:%M:%S')}".encode()
                service_ticket = Fernet(tgs_key).encrypt(service_ticket_data)
                print(f"[TGS] Emitiendo ticket de servicio para {user} al servicio {service}. Expira en: {(datetime.now() + timedelta(seconds=3)).strftime('%Y-%m-%d %H:%M:%S')}")
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



# Simulación del flujo completo
def kerberos_flow():
    # Inicializar servidores
    as_server = AuthenticationServer()
    tgs_server = TicketGrantingServer()

    # Cliente 1 solicita autenticación y servicio
    #client1 = Client('client1')
    #tgt1 = client1.request_authentication(as_server)
    #if tgt1:
        # Cliente 1 usa el TGT para solicitar un ticket de servicio
    #    client1.request_service(tgt1, tgs_server, 'FileServer')

    # Simulación de demora en Cliente 2 (espera de 5 segundos)
    

    # Cliente 2 solicita autenticación y servicio
    client2 = Client('client2')
    time.sleep(15) 
    tgt2 = client2.request_authentication(as_server)
    if tgt2:
        # Cliente 2 usa el TGT para solicitar un ticket de servicio
        client2.request_service(tgt2, tgs_server, 'FileServer')


# Ejecutar la simulación
if __name__ == "__main__":
    kerberos_flow()