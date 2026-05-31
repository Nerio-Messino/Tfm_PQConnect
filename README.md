# Tfm_PQConnect
# PQConnect Wireshark Dissector

Proyecto inicial para el desarrollo de un dissector de Wireshark orientado al análisis de tráfico generado por PQConnect, una plataforma de comunicaciones seguras basada en criptografía post-cuántica.

## Objetivo

El objetivo de este proyecto es desarrollar un dissector capaz de interpretar y visualizar tráfico generado por PQConnect dentro de Wireshark, permitiendo analizar:

- Handshakes post-cuánticos.
- Intercambio de claves.
- Mensajes de establecimiento del túnel.
- Datos cifrados.
- Estructura interna del protocolo.

Este trabajo forma parte de un Trabajo Fin de Máster relacionado con ciberseguridad y criptografía post-cuántica.

---

# Contexto

PQConnect es una plataforma desarrollada para establecer túneles seguros entre cliente y servidor utilizando criptografía resistente a ataques cuánticos.

A diferencia de protocolos tradicionales como TLS basados en RSA o ECC, PQConnect utiliza mecanismos post-cuánticos para el intercambio seguro de claves.

El objetivo del dissector es proporcionar visibilidad sobre el protocolo y facilitar la validación de su funcionamiento.

---

# Entorno de trabajo

## Máquina local

Sistema operativo:

- Windows

Herramientas instaladas:

- Wireshark
- Visual Studio Code
- Lua

## Entorno de pruebas

Se dispone de acceso a una máquina virtual Linux proporcionada por el departamento.

La máquina virtual se utilizará para:

- Instalar y ejecutar PQConnect.
- Establecer túneles cliente-servidor.
- Generar tráfico real.
- Capturar tráfico para validación del dissector.

---

# Desarrollo realizado hasta el momento

## Fase 1: Investigación

Se estudió:

- Computación cuántica.
- Amenaza sobre RSA y ECC.
- Criptografía post-cuántica.
- Funcionamiento general de PQConnect.
- Arquitectura cliente-servidor.
- Handshake post-cuántico.
- Desarrollo de dissectors para Wireshark.

También se revisaron diversos repositorios de ejemplo de dissectors en C y Lua.

---

## Fase 2: Preparación del entorno

Se verificó:

- Instalación de Wireshark.
- Soporte Lua habilitado.
- Directorio de plugins Lua de Wireshark.

Se creó el archivo:

pqconnect.lua

---

## Fase 3: Creación del primer dissector

Se implementó un dissector mínimo capaz de:

- Registrarse en Wireshark.
- Asociarse a tráfico TCP.
- Mostrar un árbol propio.
- Interpretar campos básicos.

Campos implementados:

- Version
- Message Type
- Length
- Payload

---

## Fase 4: Registro del protocolo

Se creó:

```lua
local pq = Proto("pqconnect", "PQConnect")
