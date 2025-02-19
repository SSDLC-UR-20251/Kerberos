# Kerberos Authentication

## Descripción

Kerberos es un protocolo de autenticación seguro que utiliza criptografía de clave simétrica para autenticar usuarios y servicios en una red. En este ejercicio, simularemos la interacción entre un cliente, el Authentication Server (AS) y el Ticket Granting Server (TGS).

## ¿Cómo funciona?

Se ha creado, por medio de clases, la lógica para cada uno de los componentes del protocolo: Cliente, AS y TGS. Además, se definió una base de datos en memoria para validar si los usuarios que intentan autenticarse son válidos o no. Para la generación de llaves de sesión, se ha utilizado la librería `cryptography.fernet`.

El flujo del protocolo sigue los siguientes pasos:

1. **El cliente solicita autenticarse.**
2. **El AS valida la identidad del cliente** consultando la base de datos y emite un Ticket Granting Ticket (TGT).
3. **El cliente usa el TGT** para solicitar un ticket de servicio al Ticket Granting Server (TGS).
4. **El cliente obtiene acceso al servicio** utilizando el ticket emitido por el TGS.

## Trabajo autónomo

Para mejorar la seguridad del proceso de autenticación, se debe incluir la validación de tiempos de expiración en los tickets. Las modificaciones a realizar son las siguientes:

1. **Agregar tiempo de expiración al TGT:**
   - Al crear el TGT en la variable `tgt_data`, incluir un tiempo de expiración.
   - Utilizar la librería `datetime` para obtener el tiempo actual con `now()` y añadir un intervalo (delta) de expiración (se recomienda 3 o 4 segundos para pruebas).

2. **Modificar la emisión del Service Ticket:**
   - Al descifrar el TGT, extraer el timestamp de expiración.
   - Validar si el tiempo actual es mayor al tiempo de expiración. Si el TGT ha expirado, emitir un mensaje de expiración y no generar el Service Ticket.
   - Si el TGT es válido, crear el Service Ticket y agregar un tiempo de expiración en la variable `service_ticket_data`.

3. **Verificación del Service Ticket:**
   - Cuando el cliente intente usar el Service Ticket para acceder a un servicio, descifrar el ticket con `tgs_key`.
   - Extraer el tiempo de expiración y validar si el tiempo actual es mayor al tiempo de expiración.
   - Si el ticket ha expirado, el acceso debe ser denegado.

### Prueba de implementación

Para comprobar que la implementación es correcta, realicen dos solicitudes al servicio con un intervalo de 20 segundos entre ellas:
- **La primera solicitud debe ser exitosa.**
- **La segunda solicitud debe ser rechazada debido a la expiración del ticket.**

---

## Cómo crear una rama y hacer commit desde GitHub

### 1. Crear una nueva rama en GitHub

1. Ir al repositorio en GitHub.
2. Hacer clic en el botón que muestra la rama actual (generalmente `main`).
3. En el cuadro de búsqueda, escribir el nombre de la nueva rama con el formato `feature/<nombre_apellido>`.
4. Hacer clic en "Create branch".

### 2. Modificar archivos y hacer commit en GitHub

1. Navegar hasta el archivo que se desea modificar.
2. Hacer clic en el ícono del lápiz (✏️) en la esquina superior derecha del archivo.
3. Realizar los cambios necesarios en el editor.
4. Escribir un mensaje de commit en el campo "Commit changes".
5. Seleccionar la opción "Commit directly to `feature/<nombre_apellido>`" o crear un Pull Request si es necesario.
6. Hacer clic en "Commit changes" para guardar los cambios en la nueva rama.
