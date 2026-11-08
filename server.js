const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const app = express();
const PORT = 3000;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
app.use(express.json());

// Nos debería de mostrar las solicitudes que tenga el servidor
app.use((req, res, next) => {
    console.log(`${req.method} ${req.url}`);
    next();
});

// En este archivo se deberan de guardar las tareas
const archivoTareas = path.join(__dirname, 'tareas.json');

// Con este archivo se deberian de guardar los usuarios
const archivoUsuarios = path.join(__dirname, 'usuarios.json');

// La clave para generar tokens
const JWT_SECRET = 'wow_soy_genial_wow';

// Esta funcion sirve para leer las tareas
async function leerTareas() {
    const datos = await fs.readFile(archivoTareas, 'utf8');
    return JSON.parse(datos);
}

// Esta funcion nos servirá para guardar nuestras tareas
async function guardarTareas(tareas) {
    await fs.writeFile(
        archivoTareas,
        JSON.stringify(tareas, null, 2)
    );
}

// Leeriamos a los usuarios
async function leerUsuarios() {
    const datos = await fs.readFile(archivoUsuarios, 'utf8');
    return JSON.parse(datos);
}

// Guardamos a los usuarios
async function guardarUsuarios(usuarios) {
    await fs.writeFile(
        archivoUsuarios,
        JSON.stringify(usuarios, null, 2)
    );
}

// POST: Registrar un usuario
app.post('/register', async (req, res) => {
    const usuarios = await leerUsuarios();
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Debes ingresar usuario y contraseña');
    }
    const usuarioExistente = usuarios.find(
        usuario => usuario.username === username
    );
    if (usuarioExistente) {
        return res.status(400).send('El usuario ya existe');
    }
    const passwordEncriptada = await bcrypt.hash(password, 10);
    const nuevoUsuario = {
        id: Date.now(),
        username,
        password: passwordEncriptada
    };
    usuarios.push(nuevoUsuario);
    await guardarUsuarios(usuarios);
    res.status(201).send('Usuario registrado correctamente');
});

// POST: Iniciar sesión
app.post('/login', async (req, res) => {
    const usuarios = await leerUsuarios();
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).send('Debes ingresar usuario y contraseña');
    }
    const usuario = usuarios.find(
        usuario => usuario.username === username
    );
    if (!usuario) {
        return res.status(401).send('Usuario o contraseña incorrectos');
    }
    const passwordCorrecta = await bcrypt.compare(
        password,
        usuario.password
    );
    if (!passwordCorrecta) {
        return res.status(401).send('Usuario o contraseña incorrectos');
    }
    const token = jwt.sign(
        { id: usuario.id, username: usuario.username },
        JWT_SECRET,
        { expiresIn: '1h' }
    );
    res.json({
        mensaje: 'Inicio de sesión correcto',
        token
    });
});

// Middleware para verificar el token
function autenticarToken(req, res, next) {
    const autorizacion = req.headers['authorization'];
    if (!autorizacion || !autorizacion.startsWith('Bearer ')) {
        return res.status(401).send('Acceso denegado');
    }
    const token = autorizacion.split(' ')[1];
    try {
        const usuario = jwt.verify(token, JWT_SECRET);
        req.user = usuario;
        next();
    } catch (error) {
        return res.status(403).send('Token inválido');
    }
}

// GET: Para mostrar todas las tareas
app.get('/tareas', autenticarToken, async (req, res) => {
    const tareas = await leerTareas();
    res.json(tareas);
});

// POST: Para agregar alguna tarea nueva
app.post('/tareas', autenticarToken, async (req, res) => {
    const tareas = await leerTareas();
    const { titulo, descripcion } = req.body;
    if (!titulo || !descripcion) {
        return res.status(400).send('Tienes que agregar un título y una descripción');
    }
    const nuevaTarea = {
        id: Date.now(),
        titulo,
        descripcion
    };
    tareas.push(nuevaTarea);
    await guardarTareas(tareas);
    res.status(201).json(nuevaTarea);
});

// PUT: Actualizar nuevas o tareas ya existentes
app.put('/tareas/:id', autenticarToken, async (req, res) => {
    const tareas = await leerTareas();
    const id = Number(req.params.id);
    const indice = tareas.findIndex(tarea => tarea.id === id);
    if (indice === -1) {
        return res.status(404).send('Tarea no encontrada');
    }
    tareas[indice].titulo = req.body.titulo || tareas[indice].titulo;
    tareas[indice].descripcion = req.body.descripcion || tareas[indice].descripcion;
    await guardarTareas(tareas);
    res.json(tareas[indice]);
});

// DELETE: Para que nos sea fácil eliminar tareas
app.delete('/tareas/:id', autenticarToken, async (req, res) => {
    const tareas = await leerTareas();
    const id = Number(req.params.id);
    const nuevasTareas = tareas.filter(tarea => tarea.id !== id);
    if (tareas.length === nuevasTareas.length) {
        return res.status(404).send('Tarea no encontrada');
    }
    await guardarTareas(nuevasTareas);
    res.send('Tarea eliminada correctamente');
});

// La ruta principal
app.get('/', (req, res) => {
    res.send('¡Servidor de API de tareas funcionando correctamente!');
});

// Nuestro middleware para rutas que no existen
app.use((req, res, next) => {
    const error = new Error('La ruta solicitada no existe');
    error.status = 404;
    next(error);
});

// El middleware para manejar errores
app.use((err, req, res, next) => {
    console.error('Ocurrió un error:', err.stack);
    const status = err.status || 500;
    res.status(status).json({
        mensaje: status === 404
            ? 'La ruta solicitada no existe'
            : 'Error interno en el servidor'
    });
});

// E iniciamos el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});