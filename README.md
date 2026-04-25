# API Node.js + Express con Autenticación JWT

API REST desarrollada con Node.js y Express que implementa un sistema de autenticación utilizando JSON Web Tokens (JWT) y bcrypt para el hash de contraseñas. La API está conectada a una base de datos PostgreSQL.

## Tabla de Contenidos

- [Arquitectura del Proyecto](#arquitectura-del-proyecto)
- [Descripción de Archivos](#descripción-de-archivos)
- [Configuración Local](#configuración-local)
- [Endpoints de la API](#endpoints-de-la-api)
- [Pruebas](#pruebas)
- [Despliegue en Vercel](#despliegue-en-vercel)

## Arquitectura del Proyecto

```
api-node-express/
├── index.js                    # Servidor principal y rutas de la API
├── db.js                       # Configuración de conexión a PostgreSQL
├── package.json                # Dependencias y scripts del proyecto
├── .env                        # Variables de entorno (no versionado)
├── .gitignore                  # Archivos excluidos del control de versiones
├── init_db.js                  # Inicializa la tabla de usuarios
├── inspect_db.js               # Inspecciona la estructura de la BD
└── test_api.js                 # Suite de pruebas automatizadas
```

## Descripción de Archivos

### Archivos Principales

#### `index.js` - Servidor Principal
El corazón de la aplicación. Contiene:
- Configuración de Express: Inicialización del servidor en el puerto 3000
- Middleware: body-parser para parsear JSON
- Rutas públicas: 
  - `GET /api/data` - Endpoint de prueba sin autenticación
- Rutas de autenticación:
  - `POST /api/register` - Registro de nuevos usuarios con validación y hash de contraseñas
  - `POST /api/login` - Login que genera tokens JWT con expiración de 30 minutos
- Rutas protegidas:
  - `GET /api/protected` - Requiere token JWT válido en el header Authorization
- Middleware de seguridad: `verifyToken()` para validar tokens JWT

#### `db.js` - Configuración de Base de Datos
Gestiona la conexión a PostgreSQL:
- Crea un Pool de conexiones para optimizar el rendimiento
- Lee la cadena de conexión desde `process.env.DATABASE_URL`
- Configura SSL para conexiones seguras en producción
- Exporta método `query()` para ejecutar consultas SQL

#### `package.json` - Gestión de Dependencias
Define el proyecto y sus dependencias:
- Scripts:
  - `npm start` - Inicia el servidor
- Dependencias:
  - `express` - Framework web
  - `body-parser` - Parseo de JSON
  - `jsonwebtoken` - Generación y verificación de JWT
  - `bcrypt` - Hash seguro de contraseñas
  - `pg` - Cliente de PostgreSQL
  - `dotenv` - Gestión de variables de entorno

### Scripts de Base de Datos

#### `init_db.js` - Inicialización de la Base de Datos
Script para crear la tabla `users` si no existe:
```sql
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL
);
```
**Uso**: `node init_db.js`

#### `inspect_db.js` - Inspector de Base de Datos
Consulta y muestra la estructura de la tabla `users`, incluyendo nombres de columnas y tipos de datos. Útil para debugging y verificación.

**Uso**: `node inspect_db.js`

### Archivos de Testing

#### `test_api.js` - Suite de Pruebas Automatizadas
Script completo que verifica:
1. Registro de usuario - Crea un usuario con timestamp único
2. Login exitoso - Obtiene token JWT
3. Acceso a ruta protegida - Usa el token para acceder a `/api/protected`
4. Login fallido - Verifica rechazo con contraseña incorrecta

Uso: 
```bash
node index.js  # En una terminal
node test_api.js  # En otra terminal
```

### Archivos de Configuración

#### `.env` - Variables de Entorno
Contiene configuración sensible (no se versiona en Git):
```env
DATABASE_URL=postgresql://usuario:contraseña@host:puerto/database?sslmode=require
```

#### `.gitignore` - Control de Versiones
Excluye archivos sensibles y temporales:
- `node_modules/` - Dependencias
- `.env` - Variables de entorno

## Configuración Local

### 1. Clonar el Repositorio
```bash
git clone <url-del-repositorio>
cd api-node-express
```

### 2. Instalar Dependencias
```bash
npm install
```

### 3. Configurar Variables de Entorno
Crea un archivo `.env` en la raíz del proyecto:
```env
DATABASE_URL=postgresql://usuario:contraseña@host:puerto/database?sslmode=require
```

> **Nota**: Para bases de datos en la nube (Neon, Supabase), copia la cadena de conexión desde el panel de control.

### 4. Inicializar la Base de Datos
```bash
node init_db.js
```

### 5. Iniciar el Servidor
```bash
npm start
```

Deberías ver:
```
Server started on http://localhost:3000
```

## Endpoints de la API

### Rutas Públicas

#### `GET /api/data`
Endpoint de prueba sin autenticación.

**Ejemplo**:
```bash
curl http://localhost:3000/api/data
```

**Respuesta**:
```json
{
  "message": "This is public data"
}
```

### Rutas de Autenticación

#### `POST /api/register`
Registra un nuevo usuario.

**Body (JSON)**:
```json
{
  "username": "usuario",
  "password": "contraseña"
}
```

**Ejemplo**:
```bash
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"test\", \"password\": \"test123\"}"
```

**Respuesta exitosa (201)**:
```json
{
  "message": "User registered successfully",
  "user": {
    "id": 1,
    "username": "test"
  }
}
```

**Errores posibles**:
- `400` - Username y password requeridos
- `409` - El usuario ya existe

#### `POST /api/login`
Inicia sesión y obtiene un token JWT.

**Body (JSON)**:
```json
{
  "username": "usuario",
  "password": "contraseña"
}
```

**Ejemplo**:
```bash
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"test\", \"password\": \"test123\"}"
```

**Respuesta exitosa (200)**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJ0ZXN0IiwiaWF0IjoxNjk5OTk5OTk5LCJleHAiOjE3MDAwMDE3OTl9.xxxxx"
}
```

> **Nota**: El token expira en **30 minutos**.

**Errores posibles**:
- `400` - Username y password requeridos
- `401` - Credenciales inválidas

### Rutas Protegidas

#### `GET /api/protected`
Accede a datos protegidos (requiere token JWT).

**Header requerido**:
```
Authorization: Bearer <tu-token-jwt>
```

**Ejemplo**:
```bash
curl http://localhost:3000/api/protected \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Respuesta exitosa (200)**:
```json
{
  "message": "This is protected data",
  "authData": {
    "id": 1,
    "username": "test",
    "iat": 1699999999,
    "exp": 1700001799
  }
}
```

**Errores posibles**:
- `403` - Token no proporcionado o inválido

## Pruebas

### Prueba Manual Completa

```bash
# 1. Verificar endpoint público
curl http://localhost:3000/api/data

# 2. Registrar un usuario
curl -X POST http://localhost:3000/api/register \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"testuser\", \"password\": \"password123\"}"

# 3. Hacer login y guardar el token
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"testuser\", \"password\": \"password123\"}"

# 4. Acceder a ruta protegida (reemplaza <TOKEN> con el token obtenido)
curl http://localhost:3000/api/protected \
  -H "Authorization: Bearer <TOKEN>"
```

### Pruebas Automatizadas

```bash
# Terminal 1: Iniciar servidor
npm start

# Terminal 2: Ejecutar tests
node test_api.js
```

**Salida esperada**:
```
--- Starting Verification ---
Register: PASS { message: 'User registered successfully', user: { id: 1, username: 'testuser_1699999999' } }
Login: PASS
Protected Route: PASS { message: 'This is protected data', authData: {...} }
Invalid Login: PASS
```

## Despliegue en Vercel

### 1. Instalar Vercel CLI
```bash
npm install -g vercel
```

### 2. Desplegar
```bash
vercel
```

### 3. Configurar Variables de Entorno en Vercel
En el dashboard de Vercel, añade:
- `DATABASE_URL` - Tu cadena de conexión a PostgreSQL

### 4. Probar en Producción
```bash
curl https://tu-proyecto.vercel.app/api/data
```
