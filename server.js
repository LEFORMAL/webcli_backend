// Importar los módulos necesarios
const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const mercadopago = require('mercadopago'); // Añadido para Mercado Pago
const jwt = require('jsonwebtoken');
require('dotenv').config(); // Cargar variables de entorno

// Crear una aplicación de Express
const app = express();

app.use('/css', express.static(__dirname + '/css'));
app.use('/js', express.static(__dirname + '/js'));
app.use('/assets', express.static(__dirname + '/assets'));

// Configurar CORS para permitir solicitudes desde cualquier origen
app.use(cors());

// Configurar el servidor para recibir datos en formato JSON
app.use(express.json());

// Configurar conexión a mysql Database
async function connectMySQL() {
    try {
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
            namedPlaceholders: true // Habilitar named placeholders
        });
        console.log("Conexión exitosa a MySQL");
        return connection;
    } catch (error) {
        console.error("Error al conectar con MySQL:", error);
        throw error;
    }
}

// Ruta para obtener los tipos de solicitud
app.get('/api/tipos_solicitud', async (req, res) => {
    try {
        const connection = await connectMySQL();
        const [rows] = await connection.execute('SELECT * FROM tipos_solicitud');
        await connection.end();
        res.json(rows);
    } catch (error) {
        console.error('Error al obtener los tipos de solicitud:', error);
        res.status(500).json({ error: 'Error al obtener los tipos de solicitud' });
    }
});

async function withOracleConnection(callback) {
    let connection;
    try {
        connection = await connectMySQL();
        await callback(connection);
    } catch (error) {
        console.error('Error en la base de datos:', error);
        throw error;
    } finally {
        if (connection) {
            try {
                await connection.close();
            } catch (closeError) {
                console.error('Error al cerrar la conexión:', closeError);
            }
        }
    }
}

// Configurar Mercado Pago con tu access token
mercadopago.configure({
    access_token: process.env.MERCADO_PAGO_ACCESS_TOKEN,
});

// Configurar transporte de correo con Nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

function generarToken(email) {
    return jwt.sign({ email: email }, process.env.JWT_SECRET, { expiresIn: '1h' });
}

function verificarToken(token) {
    try {
        console.log('Token recibido'); // Confirma token en la consola
        if (token.startsWith('Bearer ')) {
            token = token.slice(7, token.length).trim();
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        return { email: decoded.email, expired: false };
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            console.error('Error al verificar el token: Token expirado');
            const decoded = jwt.decode(token);
            return { email: decoded.email, expired: true };
        } else {
            console.error('Error al verificar el token:', error);
            return null;
        }
    }
}

// Ruta para registrar usuarios
app.post('/register', async (req, res) => {
    const { rut, nombres, apellidos, user_tipo, email, telefono, direccion, comuna, region, fecha_nacimiento, contrasena } = req.body;

    if (!rut || !nombres || !apellidos || !user_tipo || !email || !contrasena) {
        return res.status(400).send('Faltan campos obligatorios');
    }

    try {
        const hashedPassword = await bcrypt.hash(contrasena, 10);
        const connection = await connectMySQL();

        const sql = `INSERT INTO USUARIOS (rut, nombres, apellidos, user_tipo, email, telefono, direccion, comuna, region, fecha_nacimiento, contrasena)
                     VALUES (:rut, :nombres, :apellidos, :user_tipo, :email, :telefono, :direccion, :comuna, :region, :fecha_nacimiento, :contrasena)`;

        await connection.execute(sql, {
            rut,
            nombres,
            apellidos,
            user_tipo,
            email,
            telefono,
            direccion,
            comuna,
            region,
            fecha_nacimiento,
            contrasena: hashedPassword
        });

        res.status(200).send('Usuario registrado con éxito');
        await connection.end();
    } catch (err) {
        console.error('Error insertando usuario:', err);
        return res.status(500).send('Error al registrar el usuario');
    }
});
app.post('/login', async (req, res) => {
    const { email, contrasena } = req.body;

    if (!email || !contrasena) {
        return res.status(400).json({ message: 'Faltan campos obligatorios' });
    }

    try {
        const connection = await connectMySQL();
        const sql = 'SELECT * FROM USUARIOS WHERE email = ?';
        const [rows] = await connection.execute(sql, [email]);

        if (rows.length === 0) {
            await connection.end();
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const usuario = rows[0];
        const hashedPassword = usuario.CONTRASENA;

        console.log('Email:', email);
        console.log('Contraseña ingresada:', contrasena);
        console.log('Contraseña almacenada:', hashedPassword);

        if (!hashedPassword) {
            await connection.end();
            return res.status(500).json({ message: 'Error en el servidor: contraseña no encontrada' });
        }

        const match = await bcrypt.compare(contrasena, hashedPassword);

        console.log('Resultado de bcrypt.compare:', match);

        if (!match) {
            await connection.end();
            return res.status(401).json({ message: 'Contraseña incorrecta' });
        }

        const token = generarToken(email);

        res.status(200).json({
            message: 'Login exitoso',
            token: token,
            usuario: {
                rut: usuario.RUT,
                nombres: usuario.NOMBRES,
                apellidos: usuario.APELLIDOS,
                email: usuario.EMAIL,
                user_tipo: usuario.USER_TIPO,
                telefono: usuario.TELEFONO
            }
        });

        await connection.end();
    } catch (err) {
        console.error('Error al buscar el usuario:', err);
        return res.status(500).json({ message: 'Error en el servidor' });
    }
});

// Ruta para solicitar restablecimiento de contraseña
app.post('/request-password-reset', async (req, res) => {
    const { email } = req.body;

    try {
        const connection = await connectMySQL();
        const sql = 'SELECT * FROM USUARIOS WHERE email = ?';
        const [rows] = await connection.execute(sql, [email]);

        if (rows.length === 0) {
            await connection.end();
            return res.status(404).send('Usuario no encontrado');
        }

        // Generar token de restablecimiento y la fecha de expiración en UTC
        const token = crypto.randomBytes(20).toString('hex');
        let expiration = new Date(Date.now() + 15 * 60 * 1000); // Expira en 15 minutos

        // Convertir fecha a formato compatible con MySQL: 'YYYY-MM-DD HH:MM:SS'
        expiration = expiration.toISOString().slice(0, 19).replace('T', ' ');
        console.log('Generando token:', token);
        console.log('Fecha de expiración del token (MySQL formato):', expiration);

        // Guardar el token y la fecha de expiración en la base de datos
        await connection.execute(
            `UPDATE USUARIOS SET reset_token = ?, reset_token_expiration = ? WHERE email = ?`,
            [token, expiration, email]
        );

        await connection.end();

        // Detectar si el dispositivo es móvil o web
        const userAgent = req.headers['user-agent'];
        const isMobile = /mobile/i.test(userAgent);

        // Elegir el enlace de restablecimiento según el dispositivo
        const resetLink = isMobile 
            ? `https://leformal.github.io/webcli_frontend/movil/nueva_password.html?token=${token}&email=${email}`
            : `https://leformal.github.io/webcli_frontend/nueva_password.html?token=${token}&email=${email}`;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Restablecimiento de Contraseña',
            text: `Haga clic en el siguiente enlace para restablecer su contraseña: ${resetLink}`
        };

        await transporter.sendMail(mailOptions);
        res.status(200).send('Enlace de restablecimiento enviado');
    } catch (error) {
        console.error('Error al solicitar restablecimiento de contraseña:', error);
        res.status(500).send('Error en el servidor');
    }
});


// Ruta para asignar nueva contraseña
app.post('/nueva_password', async (req, res) => {
    const { token, email, newPassword } = req.body;

    console.log('Token recibido:', token);
    console.log('Email recibido:', email);
    console.log('Nueva contraseña recibida:', newPassword);

    try {
        const connection = await connectMySQL();

        // Verificar que el token y el email coinciden en la base de datos
        const sql = 'SELECT reset_token_expiration FROM USUARIOS WHERE email = ? AND reset_token = ?';
        const [rows] = await connection.execute(sql, [email, token]);

        if (rows.length === 0) {
            console.log('Token no coincide o usuario no encontrado');
            await connection.end();
            return res.status(400).send('Token inválido o expirado');
        }

        // Extraer y verificar la fecha de expiración del token
        const expirationDate = rows[0].reset_token_expiration;

        if (!expirationDate) {
            console.log('Fecha de expiración del token es nula o inválida');
            await connection.end();
            return res.status(400).send('Token inválido o expirado');
        }

        const expirationDateObj = new Date(expirationDate);
        const currentDate = new Date();

        console.log('Fecha de expiración del token en la base de datos (UTC):', expirationDateObj.toISOString());
        console.log('Fecha actual en el servidor (UTC):', currentDate.toISOString());

        if (currentDate > expirationDateObj) {
            console.log('Token expirado');
            await connection.end();
            return res.status(400).send('Token expirado');
        }

        // Si el token es válido y no ha expirado, actualizar la contraseña
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await connection.execute(
            'UPDATE USUARIOS SET contrasena = ?, reset_token = NULL, reset_token_expiration = NULL WHERE email = ?',
            [hashedPassword, email]
        );

        await connection.end();
        res.status(200).send('Contraseña actualizada con éxito');
    } catch (error) {
        console.error('Error al actualizar la contraseña:', error);
        res.status(500).send('Error en el servidor');
    }
});



// Ruta para obtener las marcas y modelos desde la base de datos
app.get('/api/productos', async (req, res) => {
    try {
        const connection = await connectMySQL();
        console.log("Conexión establecida correctamente");

        const sql = 'SELECT DISTINCT MARCA_PRODUCTO, MODELO_PRODUCTO, VALOR_PRODUCTO FROM PRODUCTOS ORDER BY MARCA_PRODUCTO, MODELO_PRODUCTO';
        const [rows] = await connection.execute(sql);

        console.log("Consulta exitosa");

        if (rows.length === 0) {
            console.warn("No se encontraron productos en la base de datos.");
        }

        res.json(rows);
        await connection.end();
    } catch (err) {
        console.error('Error al obtener marcas y modelos:', err);
        return res.status(500).json({ message: 'Error al obtener productos' });
    }
});

// Ruta para crear una solicitud
app.post('/api/solicitud', async (req, res) => {
    const solicitudId = crypto.randomBytes(16).toString("hex"); // Generar un ID único para la solicitud
    const datosSolicitud = req.body;

    try {
        const connection = await connectMySQL();

        // Guardar los datos en la tabla temporal
        const sqlTemp = `INSERT INTO solicitudes_temporales (solicitud_id, datos) VALUES (?, ?)`;
        await connection.execute(sqlTemp, [solicitudId, JSON.stringify(datosSolicitud)]);
        
        await connection.end();

        // Determinar URLs de redirección según el dispositivo
        const successUrl = datosSolicitud.isMobile 
    ? `https://leformal.github.io/webcli_frontend/mobile/pago_exitoso.html?solicitudId=${solicitudId}&isMobile=true` 
    : `https://leformal.github.io/webcli_frontend/pago_exitoso.html?solicitudId=${solicitudId}&isMobile=false`;

const failureUrl = datosSolicitud.isMobile 
    ? "https://leformal.github.io/webcli_frontend/mobile/pago_fallido.html" 
    : "https://leformal.github.io/webcli_frontend/pago_fallido.html";

const pendingUrl = datosSolicitud.isMobile 
    ? "https://leformal.github.io/webcli_frontend/mobile/pago_pendiente.html" 
    : "https://leformal.github.io/webcli_frontend/pago_pendiente.html";


        // Configurar preferencia de pago en Mercado Pago
        const preference = {
            items: [
                {
                    title: datosSolicitud.tipoSolicitud,
                    quantity: datosSolicitud.cantidad,
                    currency_id: 'CLP',
                    unit_price: parseFloat(datosSolicitud.costoTotal),
                },
            ],
            back_urls: {
                success: successUrl,
                failure: failureUrl,
                pending: pendingUrl,
            },
            auto_return: "approved",
            external_reference: solicitudId // Referencia para recuperar la solicitud en el pago
        };

        const response = await mercadopago.preferences.create(preference);
        const init_point = response.body.init_point;

        res.status(200).json({ message: 'Preferencia de pago creada con éxito', init_point });
    } catch (error) {
        console.error('Error al guardar la solicitud temporal:', error);
        res.status(500).json({ error: 'Error al crear la preferencia de pago', details: error.message });
    }
});


// Ruta para manejar el éxito del pago
// Ruta para manejar el éxito del pago
app.get('/api/pago_exitoso', async (req, res) => {
    const solicitudId = req.query.solicitudId;
    const isMobile = req.query.isMobile === 'true'; // Leer si es dispositivo móvil

    console.log("Solicitud exitosa recibida para solicitudId:", solicitudId);

    try {
        const connection = await connectMySQL();
        console.log("Conexión a la base de datos establecida para solicitud exitosa.");

        // Recuperar los datos de solicitud desde la tabla temporal
        const [rows] = await connection.execute(
            `SELECT datos FROM solicitudes_temporales WHERE solicitud_id = ? AND estado = 'pendiente'`,
            [solicitudId]
        );

        if (rows.length === 0) {
            console.error('Datos de solicitud no encontrados o ya procesados para solicitudId:', solicitudId);
            return res.status(404).json({ error: 'Datos de solicitud no encontrados o ya procesados' });
        }

        let datosSolicitud = rows[0].datos;
        console.log("Datos de solicitud antes de parsear:", datosSolicitud);

        if (typeof datosSolicitud === 'string') {
            datosSolicitud = JSON.parse(datosSolicitud); // Solo parseamos si es una cadena
        }
        console.log("Datos de solicitud después de parsear:", datosSolicitud);

        // Insertar la solicitud en la tabla SOLICITUD
        const sqlSolicitud = `INSERT INTO SOLICITUD (
            tipo_solicitud, fecha_solicitud, descripcion, direccion, 
            rut_usuario, nombre, rut_nit, telefono, email, 
            cantidad_productos, marca_producto, modelo_producto, 
            necesita_compra, fecha_realizacion, medio_pago, costo_total
        ) VALUES (
            ?, ?, ?, ?, 
            ?, ?, ?, ?, ?, 
            ?, ?, ?, 
            ?, ?, ?, ?
        )`;

        const [resultSolicitud] = await connection.execute(sqlSolicitud, [
            datosSolicitud.tipoSolicitud,
            datosSolicitud.fechaSolicitud,
            datosSolicitud.descripcion,
            datosSolicitud.direccion,
            datosSolicitud.rut,
            datosSolicitud.nombre,
            datosSolicitud.rut,
            datosSolicitud.telefono,
            datosSolicitud.email,
            datosSolicitud.cantidad,
            datosSolicitud.marca,
            datosSolicitud.modelo,
            datosSolicitud.necesitaCompra,
            datosSolicitud.fechaRealizacion,
            datosSolicitud.medioPago,
            datosSolicitud.costoTotal
        ]);

        const id_solicitud = resultSolicitud.insertId;
        console.log("Solicitud guardada exitosamente con ID:", id_solicitud);

        // Insertar el pago en la tabla PAGOS
        console.log("Preparando para insertar en PAGOS...");
        const sqlPago = `INSERT INTO PAGOS (
            total, medio_pago, fecha_transaccion, id_solicitud
        ) VALUES (
            ?, ?, NOW(), ?
        )`;

        await connection.execute(sqlPago, [
            datosSolicitud.costoTotal,
            datosSolicitud.medioPago,
            id_solicitud
        ]);
        console.log("Pago guardado exitosamente para la solicitud ID:", id_solicitud);

        // Actualizar el estado en la tabla temporal
        const [updateResult] = await connection.execute(
            `UPDATE solicitudes_temporales SET estado = 'completada' WHERE solicitud_id = ?`,
            [solicitudId]
        );
        console.log("Resultado de actualización:", updateResult);

        // Verificar si la actualización fue exitosa
        if (updateResult.affectedRows === 0) {
            console.warn("No se pudo actualizar el estado de la solicitud temporal para solicitudId:", solicitudId);
            return res.status(500).json({ error: 'No se pudo actualizar el estado de la solicitud temporal' });
        }

        await connection.end();

        // Redirigir a la página de éxito en función del dispositivo
        const successPage = isMobile 
            ? 'https://leformal.github.io/webcli_frontend/mobile/pago_exitoso.html' 
            : 'https://leformal.github.io/webcli_frontend/pago_exitoso.html';
        res.redirect(successPage);

    } catch (error) {
        console.error('Error al guardar la solicitud y el pago:', error);
        res.status(500).json({ error: 'Error al guardar la solicitud y el pago', details: error.message });
    }
});


// Ruta para manejar el fallo del pago
app.get('/api/pago_fallido', (req, res) => {
    const isMobile = req.query.isMobile === 'true'; // Leer si es dispositivo móvil
    const failurePage = isMobile ? '/mobile/pago_fallido.html' : '/pago_fallido.html';
    res.redirect(failurePage);
});

// Ruta para manejar el pago pendiente
app.get('/api/pago_pendiente', (req, res) => {
    const isMobile = req.query.isMobile === 'true'; // Leer si es dispositivo móvil
    const pendingPage = isMobile ? '/mobile/pago_pendiente.html' : '/pago_pendiente.html';
    res.redirect(pendingPage);
});

// Ruta para crear una solicitud y manejar el pago por transferencia
app.post('/api/solicitud_transferencia', async (req, res) => {
    const datosSolicitud = req.body;
    const solicitudId = crypto.randomBytes(16).toString("hex"); // Generar un ID único para la solicitud
    const isMobile = req.query.isMobile === 'true'; // Verificar si la solicitud es desde un dispositivo móvil

    try {
        const connection = await connectMySQL();

        // Insertar la solicitud en la tabla SOLICITUD
        const sqlSolicitud = `INSERT INTO SOLICITUD (
            TIPO_SOLICITUD, FECHA_SOLICITUD, DESCRIPCION, DIRECCION, 
            COMUNA, REGION, RUT_USUARIO, NOMBRE, RUT_NIT, 
            TELEFONO, EMAIL, CANTIDAD_PRODUCTOS, MARCA_PRODUCTO, MODELO_PRODUCTO, 
            NECESITA_COMPRA, FECHA_REALIZACION, MEDIO_PAGO, COSTO_TOTAL
        ) VALUES (
            ?, ?, ?, ?, 
            ?, ?, ?, ?, ?, 
            ?, ?, ?, ?, ?, 
            ?, ?, ?, ?
        )`;

        const [resultSolicitud] = await connection.execute(sqlSolicitud, [
            datosSolicitud.tipoSolicitud || null,
            new Date().toISOString().split('T')[0], // FECHA_SOLICITUD como la fecha actual
            datosSolicitud.descripcion || null,
            datosSolicitud.direccion || null,
            datosSolicitud.comuna || null,
            datosSolicitud.region || null,
            datosSolicitud.rut || null,
            datosSolicitud.nombre || null,
            datosSolicitud.rut || null, // Usamos el mismo RUT para RUT_NIT en este caso
            datosSolicitud.telefono || null,
            datosSolicitud.email || null,
            datosSolicitud.cantidad || 1, // Por defecto, cantidad 1 si no está especificada
            datosSolicitud.marca || null,
            datosSolicitud.modelo || null,
            datosSolicitud.necesitaCompra || 'N', // Por defecto, no necesita compra
            datosSolicitud.fechaRealizacion || null,
            'transferencia', // Medio de pago es transferencia
            datosSolicitud.costoTotal || 0 // Por defecto, costo total es 0 si no está especificado
        ]);

        const id_solicitud = resultSolicitud.insertId;

        // Insertar la transacción en la tabla PAGOS con el medio de pago "transferencia"
        const sqlPago = `INSERT INTO PAGOS (
            TOTAL, MEDIO_PAGO, FECHA_TRANSACCION, ID_SOLICITUD
        ) VALUES (
            ?, 'transferencia', NOW(), ?
        )`;

        await connection.execute(sqlPago, [
            datosSolicitud.costoTotal || 0, // De nuevo, asegurar que sea 0 si no está definido
            id_solicitud
        ]);

        await connection.end();

        // Enviar correo electrónico al usuario con los detalles para realizar la transferencia
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: datosSolicitud.email,
            subject: 'Detalles para realizar la transferencia bancaria',
            text: `Estimado/a ${datosSolicitud.nombre},

Gracias por su solicitud de servicio de ${datosSolicitud.tipoSolicitud}. Para completar su solicitud, por favor realice una transferencia bancaria con los siguientes detalles:

- Monto a Transferir: CLP ${datosSolicitud.costoTotal.toFixed(2)}
- Banco: Banco Ejemplo
- Número de Cuenta: 123456789
- Tipo de Cuenta: Cuenta Corriente
- Nombre del Beneficiario: Nombre Ejemplo
- RUT del Beneficiario: 12.345.678-9
- Asunto: ${solicitudId} (Por favor incluya este código en el asunto de la transferencia)

Una vez realizada la transferencia, por favor responda a este correo con el comprobante de pago. Nos pondremos en contacto para confirmar la recepción y proceder con la solicitud.

Saludos cordiales,
Equipo de Servicios de Climatización`
        };

        // Enviar el correo usando Nodemailer
        await transporter.sendMail(mailOptions);

        // Determinar la URL de redirección según el dispositivo
        const redirectionUrl = isMobile ? 'mobile/pagar_transferencia.html' : 'pagar_transferencia.html';

        // Configurar `Content-Type` y enviar respuesta JSON
        res.setHeader('Content-Type', 'application/json');
        res.status(200).json({
            message: 'Solicitud creada con éxito. Revisa tu correo para la información de transferencia.',
            redirectionUrl: redirectionUrl
        });
    } catch (error) {
        console.error('Error al crear la solicitud por transferencia:', error);
        res.status(500).json({ error: 'Error al procesar la solicitud de transferencia', details: error.message });
    }
});

// Ruta para actualizar perfil de usuario
app.post('/actualizarPerfil', async (req, res) => {
    const { email, nombres, apellidos, telefono, direccion, fecha_nacimiento } = req.body;
    const isMobile = req.query.isMobile === 'true'; // Verificar si la solicitud es desde un dispositivo móvil

    if (!email) {
        return res.status(400).json({ message: 'Email es requerido' });
    }

    try {
        const connection = await connectMySQL();

        // Usar placeholders compatibles con MySQL
        const sql = `UPDATE USUARIOS
                     SET NOMBRES = ?, 
                         APELLIDOS = ?, 
                         TELEFONO = ?, 
                         DIRECCION = ?, 
                         FECHA_NACIMIENTO = ?
                     WHERE EMAIL = ?`;

        await connection.execute(sql, [
            nombres,
            apellidos,
            telefono,
            direccion,
            fecha_nacimiento,  // Pasar directamente si está en formato 'YYYY-MM-DD'
            email
        ]);

        // Recuperar los datos actualizados
        const [updatedUserResult] = await connection.execute(
            'SELECT * FROM USUARIOS WHERE EMAIL = ?', [email]
        );

        const updatedUser = updatedUserResult[0];
        await connection.end();

        // Determinar la URL de redirección según el dispositivo
        const redirectionUrl = isMobile ? 'mobile/perfil_actualizado.html' : 'perfil_actualizado.html';

        // Enviar los datos actualizados al frontend
        res.status(200).json({
            message: 'Perfil actualizado',
            usuario: {
                nombres: updatedUser.NOMBRES,
                apellidos: updatedUser.APELLIDOS,
                telefono: updatedUser.TELEFONO,
                direccion: updatedUser.DIRECCION,
                fecha_nacimiento: updatedUser.FECHA_NACIMIENTO,
                email: updatedUser.EMAIL,
            },
            redirectionUrl: redirectionUrl // URL para redireccionar a la vista móvil o de escritorio
        });
    } catch (error) {
        console.error('Error al actualizar perfil:', error);
        res.status(500).json({ message: 'Error al actualizar el perfil' });
    }
});

// Ruta para obtener las solicitudes del usuario
app.get('/obtenerSolicitudes', async (req, res) => {
    const token = req.headers['authorization'];
    console.log('Token en la solicitud'); // Confirma token en la consola
    const tokenData = verificarToken(token);
    const isMobile = req.query.isMobile === 'true'; // Verificar si la solicitud es desde un dispositivo móvil

    if (!tokenData) {
        return res.status(401).json({ message: 'Token inválido' });
    }

    const { email, expired } = tokenData;

    try {
        const connection = await connectMySQL();
        const [result] = await connection.execute(
            `SELECT id_solicitud AS "ID_SOLICITUD", tipo_solicitud AS "TIPO_SOLICITUD", fecha_solicitud AS "FECHA_SOLICITUD", direccion AS "DIRECCION", comuna AS "COMUNA", region AS "REGION", rut_usuario AS "RUT_USUARIO", nombre AS "NOMBRE", rut_nit AS "RUT_NIT", telefono AS "TELEFONO", email AS "EMAIL", cantidad_productos AS "CANTIDAD_PRODUCTOS", marca_producto AS "MARCA_PRODUCTO", modelo_producto AS "MODELO_PRODUCTO", necesita_compra AS "NECESITA_COMPRA", fecha_realizacion AS "FECHA_REALIZACION", medio_pago AS "MEDIO_PAGO", costo_total AS "COSTO_TOTAL", fecha_creacion AS "FECHA_CREACION" FROM SOLICITUD WHERE email = ?`,
            [email]
        );

        console.log('Solicitudes obtenidas'); // Confirma datos obtenidos

        const responsePayload = {
            solicitudes: result,
            redirectionUrl: isMobile ? 'mobile/solicitudes.html' : 'solicitudes.html'
        };

        if (expired) {
            const newToken = generarToken(email);
            responsePayload.newToken = newToken;
        }

        res.json(responsePayload);

        await connection.close();
    } catch (error) {
        console.error('Error al obtener las solicitudes:', error);
        res.status(500).send('Error al obtener las solicitudes');
    }
});

// Ruta para probar la conexión a la base de datos
app.get('/test-db-connection', async (req, res) => {
    try {
        const connection = await connectMySQL();
        await connection.query('SELECT 1'); // Consulta simple para probar la conexión
        await connection.end();
        res.status(200).send('Conexión a la base de datos exitosa');
    } catch (error) {
        console.error('Error al conectar con la base de datos:', error);
        res.status(500).send('Error al conectar con la base de datos');
    }
});


// Servidor en puerto 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en ejecución en el puerto ${PORT}`));

function createMercadoPagoPreference(tipoSolicitud, cantidad, costoTotal) {
    return {
        items: [
            {
                title: tipoSolicitud,
                quantity: cantidad,
                currency_id: 'CLP',
                unit_price: costoTotal,
            },
        ],
        back_urls: {
            success: "http://localhost:3000/pago_exitoso",
            failure: "http://localhost:3000/pago_fallido",
            pending: "http://localhost:3000/pago_pendiente",
        },
        auto_return: "approved",
    };
}

