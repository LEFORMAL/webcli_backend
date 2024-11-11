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

// Configurar conexión a Oracle Database
async function connectMySQL() {
    try {
        const connection = await mysql.createConnection({
            host: process.env.DB_HOST,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME
        });
        console.log("Conexión exitosa a MySQL");
        return connection;
    } catch (error) {
        console.error("Error al conectar con MySQL:", error);
        throw error;
    }
}

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
        return decoded.email;
    } catch (error) {
        console.error('Error al verificar el token:', error);
        return null;
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

        const sql = `INSERT INTO usuarios (rut, nombres, apellidos, user_tipo, email, telefono, direccion, comuna, region, fecha_nacimiento, contrasena)
                     VALUES (:rut, :nombres, :apellidos, :user_tipo, :email, :telefono, :direccion, :comuna, :region, TO_DATE(:fecha_nacimiento, 'YYYY-MM-DD'), :contrasena)`;

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
        }, { autoCommit: true });

        res.status(200).send('Usuario registrado con éxito');
        await connection.close();
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
        const sql = 'SELECT * FROM usuarios WHERE email = :email';
        const result = await connection.execute(sql, [email]);

        if (result.rows.length === 0) {
            await connection.close();
            return res.status(404).json({ message: 'Usuario no encontrado' });
        }

        const usuario = result.rows[0];
        const hashedPassword = usuario.CONTRASENA || usuario[10]; // Cambia el índice 10 si es necesario

        const match = await bcrypt.compare(contrasena, hashedPassword);

        if (!match) {
            await connection.close();
            return res.status(401).json({ message: 'Contraseña incorrecta' });
        }

        const token = generarToken(email);

        res.status(200).json({
            message: 'Login exitoso',
            token: token,
            usuario: {
                rut: usuario.RUT || usuario[0],
                nombres: usuario.NOMBRES || usuario[1],
                apellidos: usuario.APELLIDOS || usuario[2],
                email: usuario.EMAIL || usuario[4],
                user_tipo: usuario.USER_TIPO || usuario[3],
                telefono: usuario.TELEFONO || usuario[5]
            }
        });

        await connection.close();
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
        const sql = 'SELECT * FROM usuarios WHERE email = :email';
        const result = await connection.execute(sql, [email]);

        if (result.rows.length === 0) {
            await connection.close();
            return res.status(404).send('Usuario no encontrado');
        }

        // Generar token de restablecimiento
        const token = crypto.randomBytes(20).toString('hex');
        const expiration = new Date(Date.now() + 15 * 60 * 1000); // Expira en 15 minutos

        // Guardar token en la base de datos
        await connection.execute(
            `UPDATE usuarios SET reset_token = :token, reset_token_expiration = :expiration WHERE email = :email`,
            { token, expiration, email },
            { autoCommit: true }
        );

        // Enviar el enlace de restablecimiento por correo
        const resetLink = `http://localhost:3000/nueva_password?token=${token}&email=${email}`;
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

// Ruta para obtener las marcas y modelos desde la base de datos
app.get('/api/productos', async (req, res) => {
    try {
        const connection = await connectMySQL();
        console.log("Conexión establecida correctamente");

        const sql = 'SELECT DISTINCT MARCA_PRODUCTO, MODELO_PRODUCTO, valor_producto FROM PRODUCTOS ORDER BY MARCA_PRODUCTO, MODELO_PRODUCTO';
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
    const {
        nombre, rut, telefono, email, direccion, cantidad,
        marca, modelo, necesitaCompra, tipoSolicitud,
        fechaSolicitud, fechaRealizacion, descripcion, medioPago, costoTotal
    } = req.body;

    try {
        // Generar la preferencia de pago en Mercado Pago
        const preference = {
            items: [
                {
                    title: tipoSolicitud,
                    quantity: cantidad,
                    currency_id: 'CLP',
                    unit_price: costoTotal,
                },
            ],
            back_urls: {
                success: "http://localhost:3000/api/pago_exitoso",
                failure: "http://localhost:3000/api/pago_fallido",
                pending: "http://localhost:3000/api/pago_pendiente",
            },
            auto_return: "approved",
        };

        // Crear preferencia en Mercado Pago
        const response = await mercadopago.preferences.create(preference);
        const init_point = response.body.init_point;

        // Enviar el enlace de pago si todo fue exitoso
        res.status(200).json({ message: 'Preferencia de pago creada con éxito', init_point });
    } catch (error) {
        console.error('Error al crear la preferencia de pago:', error);
        res.status(500).json({ error: 'Error al crear la preferencia de pago', details: error.message });
    }
});
// Ruta para crear una solicitud con pago por transferencia
app.post('/api/solicitud_transferencia', async (req, res) => {
    const {
        nombre, rut, telefono, email, direccion, cantidad,
        marca, modelo, necesitaCompra, tipoSolicitud,
        fechaSolicitud, fechaRealizacion, descripcion, medioPago, costoTotal
    } = req.body;

    try {
        const connection = await connectMySQL();

        // Verificar si el usuario está registrado
        const sqlUsuario = 'SELECT * FROM usuarios WHERE rut = :rut';
        const resultUsuario = await connection.execute(sqlUsuario, { rut });

        let rutUsuario = rut;

        if (resultUsuario.rows.length === 0) {
            // Insertar un nuevo usuario invitado
            const sqlInsertInvitado = `INSERT INTO invitados (id_invitado, nombre, rut, telefono, email, direccion)
                                       VALUES (invitados_seq.NEXTVAL, :nombre, :rut, :telefono, :email, :direccion)`;
            await connection.execute(sqlInsertInvitado, {
                nombre,
                rut,
                telefono,
                email,
                direccion
            }, { autoCommit: true });

            // Usar el RUT del invitado para la solicitud
            rutUsuario = rut;
        }

        // Insertar la solicitud en la tabla SOLICITUD
        const sqlSolicitud = `INSERT INTO solicitud (
            tipo_solicitud, fecha_solicitud, descripcion, direccion, 
            rut_usuario, nombre, rut_nit, telefono, email, 
            cantidad_productos, marca_producto, modelo_producto, 
            necesita_compra, fecha_realizacion, medio_pago, costo_total
        ) VALUES (
            :tipo_solicitud, TO_DATE(:fecha_solicitud, 'YYYY-MM-DD'), :descripcion, :direccion, 
            :rut_usuario, :nombre, :rut, :telefono, :email, 
            :cantidad, :marca, :modelo, 
            :necesitaCompra, TO_DATE(:fecha_realizacion, 'YYYY-MM-DD'), :medio_pago, :costo_total
        ) RETURNING id_solicitud INTO :id_solicitud`;

        const resultSolicitud = await connection.execute(sqlSolicitud, {
            tipo_solicitud: tipoSolicitud,
            fecha_solicitud: fechaSolicitud,
            descripcion,
            direccion,
            rut_usuario: rutUsuario,
            nombre,
            rut,
            telefono,
            email,
            cantidad,
            marca,
            modelo,
            necesitaCompra: necesitaCompra ? 'Y' : 'N',
            fecha_realizacion: fechaRealizacion,
            medio_pago: medioPago,
            costo_total: costoTotal,
            id_solicitud: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER }
        }, { autoCommit: true });

        const id_solicitud = resultSolicitud.outBinds.id_solicitud[0];

        await connection.close();

        // Enviar el correo electrónico con la información de transferencia
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Información de Transferencia Bancaria',
            text: `Estimado ${nombre},\n\nGracias por su solicitud de servicio. A continuación, encontrará la información para realizar la transferencia bancaria:\n\nBanco: [Nombre del Banco]\nCuenta: [Número de Cuenta]\nTitular: [Nombre del Titular]\nMonto: $${costoTotal}\n\nPor favor, envíe el comprobante de la transferencia a este correo electrónico para confirmar su solicitud.\n\nSaludos,\n[Nombre de la Empresa]`
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: 'Solicitud creada con éxito' });
    } catch (error) {
        console.error('Error al crear la solicitud:', error);
        res.status(500).json({ error: 'Error al crear la solicitud', details: error.message });
    }
});

// Ruta para manejar el éxito del pago
app.get('/api/pago_exitoso', async (req, res) => {
    const { collection_id, collection_status, external_reference, payment_type, merchant_order_id } = req.query;

    try {
        const connection = await connectMySQL();

        // Insertar la solicitud en la tabla SOLICITUD
        const sqlSolicitud = `INSERT INTO solicitud (
            tipo_solicitud, fecha_solicitud, descripcion, direccion, 
            rut_usuario, nombre, rut_nit, telefono, email, 
            cantidad_productos, marca_producto, modelo_producto, 
            necesita_compra, fecha_realizacion, medio_pago, costo_total
        ) VALUES (
            :tipo_solicitud, TO_DATE(:fecha_solicitud, 'YYYY-MM-DD'), :descripcion, :direccion, 
            :rut, :nombre, :rut, :telefono, :email, 
            :cantidad, :marca, :modelo, 
            :necesitaCompra, TO_DATE(:fecha_realizacion, 'YYYY-MM-DD'), :medio_pago, :costo_total
        ) RETURNING id_solicitud INTO :id_solicitud`;

        const resultSolicitud = await connection.execute(sqlSolicitud, {
            tipo_solicitud: req.body.tipoSolicitud,
            fecha_solicitud: req.body.fechaSolicitud,
            descripcion: req.body.descripcion,
            direccion: req.body.direccion,
            rut: req.body.rut,
            nombre: req.body.nombre,
            telefono: req.body.telefono,
            email: req.body.email,
            cantidad: req.body.cantidad,
            marca: req.body.marca,
            modelo: req.body.modelo,
            necesitaCompra: req.body.necesitaCompra ? 'Y' : 'N',
            fecha_realizacion: req.body.fechaRealizacion,
            medio_pago: req.body.medioPago,
            costo_total: req.body.costoTotal,
            id_solicitud: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER }
        }, { autoCommit: true });

        const id_solicitud = resultSolicitud.outBinds.id_solicitud[0];

        // Insertar el pago en la tabla PAGOS
        const sqlPago = `INSERT INTO pagos (
            total, medio_pago, fecha_transaccion, id_solicitud
        ) VALUES (
            :total, :medio_pago, SYSDATE, :id_solicitud
        ) RETURNING id_transaccion INTO :id_transaccion`;

        const resultPago = await connection.execute(sqlPago, {
            total: req.body.costoTotal,
            medio_pago: req.body.medioPago,
            id_solicitud: id_solicitud,
            id_transaccion: { dir: oracledb.BIND_OUT, type: oracledb.NUMBER }
        }, { autoCommit: true });

        const id_transaccion = resultPago.outBinds.id_transaccion[0];

        await connection.close();

        // Redirigir a la página de éxito
        res.redirect('/pago_exitoso.html');
    } catch (error) {
        console.error('Error al guardar la solicitud y el pago:', error);
        res.status(500).json({ error: 'Error al guardar la solicitud y el pago', details: error.message });
    }
});

// Ruta para manejar el fallo del pago
app.get('/api/pago_fallido', (req, res) => {
    res.redirect('/pago_fallido.html');
});

// Ruta para manejar el pago pendiente
app.get('/api/pago_pendiente', (req, res) => {
    res.redirect('/pago_pendiente.html');
});

// Ruta para actualizar perfil de usuario
app.post('/actualizarPerfil', async (req, res) => {
    const { email, nombres, apellidos, telefono, direccion, fecha_nacimiento } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email es requerido' });
    }

    try {
        const connection = await connectMySQL();

        const sql = `UPDATE usuarios 
                     SET nombres = :nombres,
                         apellidos = :apellidos,
                         telefono = :telefono,
                         direccion = :direccion,
                         fecha_nacimiento = TO_DATE(:fecha_nacimiento, 'YYYY-MM-DD')
                     WHERE email = :email`;

        await connection.execute(sql, {
            nombres,
            apellidos,
            telefono,
            direccion,
            fecha_nacimiento,
            email,
        }, { autoCommit: true });

        // Recuperar los datos actualizados
        const updatedUserResult = await connection.execute(
            'SELECT * FROM usuarios WHERE email = :email', [email]
        );

        const updatedUser = updatedUserResult.rows[0];
        await connection.close();

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
            }
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
    const email = verificarToken(token);

    if (!email) {
        return res.status(401).send('Token inválido o expirado');
    }

    try {
        const connection = await connectMySQL();
        const result = await connection.execute(
            `SELECT id_solicitud AS "ID_SOLICITUD", tipo_solicitud AS "TIPO_SOLICITUD", fecha_solicitud AS "FECHA_SOLICITUD", direccion AS "DIRECCION", comuna AS "COMUNA", region AS "REGION", rut_usuario AS "RUT_USUARIO", nombre AS "NOMBRE", rut_nit AS "RUT_NIT", telefono AS "TELEFONO", email AS "EMAIL", cantidad_productos AS "CANTIDAD_PRODUCTOS", marca_producto AS "MARCA_PRODUCTO", modelo_producto AS "MODELO_PRODUCTO", necesita_compra AS "NECESITA_COMPRA", fecha_realizacion AS "FECHA_REALIZACION", medio_pago AS "MEDIO_PAGO", costo_total AS "COSTO_TOTAL", fecha_creacion AS "FECHA_CREACION" FROM solicitud WHERE email = :email`,
            [email]
        );

        console.log('Solicitudes obtenidas'); // Confirma datos obtenidos
        res.json(result.rows);
        await connection.close();
    } catch (error) {
        console.error('Error al obtener las solicitudes:', error);
        res.status(500).send('Error al obtener las solicitudes');
    }
});

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

