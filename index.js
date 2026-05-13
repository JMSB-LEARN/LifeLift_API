const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors'); // Declarado solo una vez
const db = require('./db');

const app = express();
const port = 3000;
const secretKey = process.env.JWT_SECRET;

if (!secretKey) {
  console.error('JWT_SECRET no está definido. Crea un archivo .env con JWT_SECRET=tu-clave-secreta');
  process.exit(1);
}


app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://life-lift.vercel.app');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

// CONFIGURACIÓN DE CORS
app.use(cors({
  origin: 'https://life-lift.vercel.app',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// MANEJO DE PREFLIGHT
app.options('*', cors());

// PARSERS DE CUERPO
app.use(bodyParser.json({ limit: '20mb' }));
app.use(bodyParser.urlencoded({ limit: '20mb', extended: true }));

// Ruta publica
app.get('/api/data', (req, res) => {
  res.json({ message: 'Prueba de que el servidor funciona!' });
});

// Ruta de registro
app.post('/api/register', async (req, res) => {
  const { username, email, password, first_name, surname_1, surname_2, document_number, document_type, birth_date } = req.body;

  // Validar campos obligatorios
  if (!username || !email || !password || !first_name || !surname_1 || !document_number || !birth_date) {
    return res.status(400).json({
      message: 'Faltan campos obligatorios para el registro'
    });
  }

  try {
    // Verificar si el nombre de usuario ya existe
    const usernameCheck = await db.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    if (usernameCheck.rows.length > 0) {
      return res.status(409).json({
        message: 'Nombre de usuario ya existe'
      });
    }

    // Verificar si el correo electrónico ya existe
    const emailCheck = await db.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (emailCheck.rows.length > 0) {
      return res.status(409).json({
        message: 'El correo electrónico ya existe'
      });
    }

    // Hashea la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Inserta el nuevo usuario en la base de datos
    const newUser = await db.query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, created_at`,
      [username, email, hashedPassword]
    );

    // Inserta el perfil
    await db.query(
      `INSERT INTO profiles (
        user_id, first_name, surname_1, surname_2, birth_date, document_number, document_type
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [newUser.rows[0].id, first_name, surname_1, surname_2 || null, birth_date, document_number, document_type || 'DNI']
    );

    await recalculateMatchesForUser(newUser.rows[0].id);

    res.status(201).json({
      message: 'Usuario registrado exitosamente. Perfil creado.',
      user: newUser.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: 'Error al registrar el usuario'
    });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Se requiere nombre de usuario y contraseña' });
  }

  try {
    const result = await db.query(`
      SELECT u.*, p.first_name, p.surname_1 as surname, p.surname_2 as second_surname 
      FROM users u 
      LEFT JOIN profiles p ON u.id = p.user_id 
      WHERE u.username = $1
    `, [username]);

    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ message: 'Nombre de usuario o contraseña inválidos' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ message: 'Nombre de usuario o contraseña inválidos' });
    }

    jwt.sign({ id: user.id, username: user.username }, secretKey, { expiresIn: '24h' }, (err, token) => {
      if (err) {
        return res.status(500).json({ message: 'Error al generar el token' });
      }
      res.json({
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          first_name: user.first_name,
          surname: user.surname,
          second_surname: user.second_surname
        }
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al iniciar sesión' });
  }
});

// Ruta para cambiar contraseña
app.put('/api/change-password', verifyToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Se requiere contraseña actual y nueva contraseña' });
  }

  try {
    const result = await db.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ message: 'Contraseña actual inválida' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedNewPassword, req.user.id]);

    res.json({ message: 'Contraseña cambiada exitosamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al cambiar la contraseña' });
  }
});

// Ruta protegida
app.get('/api/protected', verifyToken, (req, res) => {
  res.json({
    message: 'Datos protegidos',
    authData: req.user
  });
});

// Middleware para verificar token
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader !== 'undefined') {
    const bearerToken = bearerHeader.split(' ')[1];
    jwt.verify(bearerToken, secretKey, (err, authData) => {
      if (err) {
        return res.sendStatus(403);
      }
      req.user = authData;
      next();
    });
  } else {
    res.sendStatus(403);
  }
}

// RUTAS DE PERFILES

app.get('/api/profile', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM profiles WHERE user_id = $1', [req.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Perfil no encontrado' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener el perfil' });
  }
});

app.post('/api/profile', verifyToken, async (req, res) => {
  const {
    first_name, surname_1, surname_2, birth_date, document_number,
    document_type, phone, address, postal_code, province, autonomous_community,
    is_gender_violence_victim
  } = req.body;

  try {
    const check = await db.query('SELECT * FROM profiles WHERE user_id = $1', [req.user.id]);
    if (check.rows.length > 0) {
      return res.status(409).json({ message: 'El perfil ya existe. Usa PUT para actualizar.' });
    }

    const result = await db.query(
      `INSERT INTO profiles (
        user_id, first_name, surname_1, surname_2, birth_date, document_number,
        document_type, phone, address, postal_code, province, autonomous_community,
        is_gender_violence_victim
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING *`,
      [req.user.id, first_name, surname_1, surname_2, birth_date, document_number, document_type, phone, address, postal_code, province, autonomous_community, is_gender_violence_victim]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al crear el perfil' });
  }
});

app.put('/api/profile', verifyToken, async (req, res) => {
  const {
    first_name, surname_1, surname_2, birth_date, document_number,
    document_type, phone, address, postal_code, province, autonomous_community,
    is_gender_violence_victim
  } = req.body;

  try {
    const result = await db.query(
      `UPDATE profiles SET 
        first_name = COALESCE($1, first_name),
        surname_1 = COALESCE($2, surname_1),
        surname_2 = COALESCE($3, surname_2),
        birth_date = COALESCE($4, birth_date),
        document_number = COALESCE($5, document_number),
        document_type = COALESCE($6, document_type),
        phone = COALESCE($7, phone),
        address = COALESCE($8, address),
        postal_code = COALESCE($9, postal_code),
        province = COALESCE($10, province),
        autonomous_community = COALESCE($11, autonomous_community),
        is_gender_violence_victim = COALESCE($12, is_gender_violence_victim)
       WHERE user_id = $13 RETURNING *`,
      [first_name, surname_1, surname_2, birth_date, document_number, document_type, phone, address, postal_code, province, autonomous_community, is_gender_violence_victim, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Perfil no encontrado' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al actualizar el perfil' });
  }
});


// RUTA DATOS SOCIO ECONOMICOS 


app.get('/api/socio-economic', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM socio_economic_data WHERE user_id = $1', [req.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Datos socio-económicos no encontrados' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener los datos socio-económicos' });
  }
});

app.post('/api/socio-economic', verifyToken, async (req, res) => {
  const {
    education_level, employment_status, gross_annual_income, is_large_family,
    large_family_category, has_disability, disability_percentage,
    is_single_parent, exclusion_risk, dependency_grade, number_of_children
  } = req.body;

  try {
    const check = await db.query('SELECT * FROM socio_economic_data WHERE user_id = $1', [req.user.id]);
    if (check.rows.length > 0) {
      return res.status(409).json({ message: 'Los datos socio-económicos ya existen. Usa PUT para actualizar.' });
    }

    const result = await db.query(
      `INSERT INTO socio_economic_data (
        user_id, education_level, employment_status, gross_annual_income, is_large_family,
        large_family_category, has_disability, disability_percentage, is_single_parent, exclusion_risk,
        dependency_grade, number_of_children
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [req.user.id, education_level, employment_status, gross_annual_income, is_large_family, large_family_category, has_disability, disability_percentage, is_single_parent, exclusion_risk, dependency_grade, number_of_children]
    );

    await recalculateMatchesForUser(req.user.id);

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al crear los datos socio-económicos' });
  }
});

app.put('/api/socio-economic', verifyToken, async (req, res) => {
  const {
    education_level, employment_status, gross_annual_income, is_large_family,
    large_family_category, has_disability, disability_percentage,
    is_single_parent, exclusion_risk, dependency_grade, number_of_children
  } = req.body;

  try {
    const result = await db.query(
      `UPDATE socio_economic_data SET 
        education_level = COALESCE($1, education_level),
        employment_status = COALESCE($2, employment_status),
        gross_annual_income = COALESCE($3, gross_annual_income),
        is_large_family = COALESCE($4, is_large_family),
        large_family_category = COALESCE($5, large_family_category),
        has_disability = COALESCE($6, has_disability),
        disability_percentage = COALESCE($7, disability_percentage),
        is_single_parent = COALESCE($8, is_single_parent),
        exclusion_risk = COALESCE($9, exclusion_risk),
        dependency_grade = COALESCE($10, dependency_grade),
        number_of_children = COALESCE($11, number_of_children)
       WHERE user_id = $12 RETURNING *`,
      [education_level, employment_status, gross_annual_income, is_large_family, large_family_category, has_disability, disability_percentage, is_single_parent, exclusion_risk, dependency_grade, number_of_children, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Datos socio-económicos no encontrados' });
    }

    await recalculateMatchesForUser(req.user.id);

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al actualizar los datos socio-económicos' });
  }
});


// RUTAS CONVIVIENTES

app.get('/api/housemates', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM housemates WHERE user_id = $1 ORDER BY id ASC', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener los convivientes' });
  }
});

app.post('/api/housemates', verifyToken, async (req, res) => {
  const {
    full_name, relation, document_number, lives_with, is_dependent, income_annual, birth_date
  } = req.body;

  try {
    const result = await db.query(
      `INSERT INTO housemates (
        user_id, full_name, relation, document_number, lives_with, is_dependent, income_annual, birth_date
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [req.user.id, full_name, relation, document_number, lives_with, is_dependent, income_annual, birth_date]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al crear un conviviente' });
  }
});

app.put('/api/housemates/:id', verifyToken, async (req, res) => {
  const housemateId = req.params.id;
  const {
    full_name, relation, document_number, lives_with, is_dependent, income_annual, birth_date
  } = req.body;

  try {
    const result = await db.query(
      `UPDATE housemates SET 
        full_name = COALESCE($1, full_name),
        relation = COALESCE($2, relation),
        document_number = COALESCE($3, document_number),
        lives_with = COALESCE($4, lives_with),
        is_dependent = COALESCE($5, is_dependent),
        income_annual = COALESCE($6, income_annual),
        birth_date = COALESCE($7, birth_date)
       WHERE id = $8 AND user_id = $9 RETURNING *`,
      [full_name, relation, document_number, lives_with, is_dependent, income_annual, birth_date, housemateId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Conviviente no encontrado' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al actualizar el conviviente' });
  }
});

app.delete('/api/housemates/:id', verifyToken, async (req, res) => {
  const housemateId = req.params.id;

  try {
    const result = await db.query(
      'DELETE FROM housemates WHERE id = $1 AND user_id = $2 RETURNING id',
      [housemateId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Conviviente no encontrado' });
    }
    res.json({ message: 'Conviviente eliminado exitosamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al eliminar el conviviente' });
  }
});


// RUTAS DE AYUDAS GUBERNAMENTALES 


app.get('/api/grants', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM government_grants ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener las ayudas' });
  }
});

app.get('/api/grants/:id', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM government_grants WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Ayuda no encontrada' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener la ayuda' });
  }
});


// RUTAS DE SOLICITUDES 

app.get('/api/applications', verifyToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT id, user_id, grant_id, status, amount_granted, application_ref_number, 
             notes, applied_at, created_at, updated_at,
             (document_pdf IS NOT NULL) as has_document
      FROM user_applications 
      WHERE user_id = $1 
      ORDER BY created_at DESC
    `, [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener las solicitudes' });
  }
});

app.post('/api/applications', verifyToken, async (req, res) => {
  const { grant_id, status, amount_granted, application_ref_number, notes, applied_at } = req.body;

  if (!grant_id) {
    return res.status(400).json({ message: 'Se requiere grant_id' });
  }

  try {
    const result = await db.query(
      `INSERT INTO user_applications (
        user_id, grant_id, status, amount_granted, application_ref_number, notes, applied_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [req.user.id, grant_id, status || 'interested', amount_granted || 0, application_ref_number, notes, applied_at]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al crear la solicitud' });
  }
});

app.put('/api/applications/:id', verifyToken, async (req, res) => {
  const applicationId = req.params.id;
  const { status, amount_granted, application_ref_number, notes, applied_at } = req.body;

  try {
    const result = await db.query(
      `UPDATE user_applications SET 
        status = COALESCE($1, status),
        amount_granted = COALESCE($2, amount_granted),
        application_ref_number = COALESCE($3, application_ref_number),
        notes = COALESCE($4, notes),
        applied_at = COALESCE($5, applied_at),
        updated_at = NOW()
       WHERE id = $6 AND user_id = $7 RETURNING *`,
      [status, amount_granted, application_ref_number, notes, applied_at, applicationId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Solicitud no encontrada' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al actualizar la solicitud' });
  }
});

// Ruta para subir documento PDF de la solicitud
app.put('/api/applications/:id/document', verifyToken, async (req, res) => {
  const applicationId = req.params.id;
  const { document_pdf, document_name } = req.body; 

  if (!document_pdf) {
    return res.status(400).json({ message: 'Se requiere document_pdf' });
  }

  try {
    const base64Data = document_pdf.replace(/^data:application\/pdf;base64,/, "");
    const buffer = Buffer.from(base64Data, 'base64');

    await db.query(
      'UPDATE user_applications SET document_pdf = $1, document_name = $2 WHERE id = $3 AND user_id = $4',
      [buffer, document_name, applicationId, req.user.id]
    );
    res.json({ message: 'Documento subido exitosamente' });
  } catch (err) {
    res.status(500).json({ message: 'Error al subir el documento' });
  }
});

// Ruta para eliminar el documento PDF de la solicitud
app.delete('/api/applications/:id/document', verifyToken, async (req, res) => {
  const applicationId = req.params.id;

  try {
    const result = await db.query(
      'UPDATE user_applications SET document_pdf = NULL, document_name = NULL WHERE id = $1 AND user_id = $2 RETURNING id',
      [applicationId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Solicitud no encontrada' });
    }
    res.json({ message: 'Documento eliminado exitosamente' });
  } catch (err) {
    res.status(500).json({ message: 'Error al eliminar el documento' });
  }
});



// Ruta para obtener el documento PDF de la solicitud
app.get('/api/applications/:id/document', verifyToken, async (req, res) => {
  const applicationId = req.params.id;

  try {
    const result = await db.query('SELECT document_pdf FROM user_applications WHERE id = $1 AND user_id = $2', [applicationId, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Solicitud no encontrada' });
    }

    const doc = result.rows[0].document_pdf;
    if (!doc) {
      return res.status(404).json({ message: 'No se adjuntó ningún documento' });
    }

    const base64 = doc.toString('base64');
    res.json({ document_pdf: `data:application/pdf;base64,${base64}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener el documento' });
  }
});

app.delete('/api/applications/:id', verifyToken, async (req, res) => {
  const applicationId = req.params.id;

  try {
    const result = await db.query(
      'DELETE FROM user_applications WHERE id = $1 AND user_id = $2 RETURNING id',
      [applicationId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Solicitud no encontrada' });
    }
    res.json({ message: 'Solicitud eliminada exitosamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al eliminar la solicitud' });
  }
});


// RUTAS DE AYUDAS GUBERNAMENTALES 


app.get('/api/grant-matches', verifyToken, async (req, res) => {
  try {
    const result = await db.query(`
      SELECT gm.*, gg.title, gg.description, gg.min_amount, gg.max_amount, gg.opening_date, gg.closing_date 
      FROM grant_matches gm
      JOIN government_grants gg ON gm.grant_id = gg.id
      WHERE gm.user_id = $1
      ORDER BY gm.eligibility_score DESC, gm.calculated_at DESC
    `, [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al obtener las ayudas' });
  }
});

app.post('/api/grant-matches', verifyToken, async (req, res) => {
  const { grant_id, eligibility_score, is_eligible, reasons } = req.body;

  if (!grant_id) {
    return res.status(400).json({ message: 'Se requiere grant_id' });
  }

  try {
    const result = await db.query(
      `INSERT INTO grant_matches (
        user_id, grant_id, eligibility_score, is_eligible, reasons
      ) VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [req.user.id, grant_id, eligibility_score || 0, is_eligible || false, reasons || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al crear el match de ayudas' });
  }
});

app.put('/api/grant-matches/:id', verifyToken, async (req, res) => {
  const matchId = req.params.id;
  const { eligibility_score, is_eligible, reasons } = req.body;

  try {
    const result = await db.query(
      `UPDATE grant_matches SET 
        eligibility_score = COALESCE($1, eligibility_score),
        is_eligible = COALESCE($2, is_eligible),
        reasons = COALESCE($3, reasons),
        calculated_at = NOW()
       WHERE id = $4 AND user_id = $5 RETURNING *`,
      [eligibility_score, is_eligible, reasons, matchId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Match de ayudas no encontrado' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al actualizar el match de ayudas' });
  }
});

app.delete('/api/grant-matches/:id', verifyToken, async (req, res) => {
  const matchId = req.params.id;

  try {
    const result = await db.query(
      'DELETE FROM grant_matches WHERE id = $1 AND user_id = $2 RETURNING id',
      [matchId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Match de ayudas no encontrado' });
    }
    res.json({ message: 'Match de ayudas eliminado exitosamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error al eliminar el match de ayudas' });
  }
});

// UTILIDADES


function parseEligibilityRules(title, description) {
  const text = (title + ' ' + description).toLowerCase();
  const rules = {};

  if (text.includes('monoparental') || text.includes('monomarental')) {
    rules.is_single_parent = true;
  }
  if (text.includes('desempleo') || text.includes('desempleado') || text.includes('desempleada') || text.match(/\bparo\b/)) {
    rules.employment_status = 'unemployed';
  }
  if (text.includes('discapacidad') || text.includes('discapacitado') || text.includes('minusvalía')) {
    rules.has_disability = true;
  }
  if (text.includes('familia numerosa')) {
    rules.is_large_family = true;
  }
  if (text.includes('exclusión social') || text.includes('vulnerabilidad')) {
    rules.exclusion_risk = true;
  }

  return Object.keys(rules).length > 0 ? rules : null;
}

function calculateGrantScore(userSocioEconomicData, eligibilityRules) {
  let score = 50;
  let is_eligible = true;
  const reasons = [];

  if (!eligibilityRules || Object.keys(eligibilityRules).length === 0) {
    reasons.push('Cumple requisitos generales (no hay requisitos específicos).');
    return { score, is_eligible, reasons };
  }

  const userData = userSocioEconomicData || {};

  if (eligibilityRules.is_single_parent) {
    if (userData.is_single_parent) {
      score += 20;
      reasons.push('Cumples el requisito de familia monoparental.');
    } else {
      score = 0;
      is_eligible = false;
      reasons.push('No cumples el requisito de familia monoparental.');
    }
  }

  if (eligibilityRules.has_disability) {
    if (userData.has_disability) {
      score += 20;
      reasons.push('Cumples el requisito de discapacidad.');
    } else {
      score = 0;
      is_eligible = false;
      reasons.push('No cumples el requisito de discapacidad.');
    }
  }

  if (eligibilityRules.is_large_family) {
    if (userData.is_large_family) {
      score += 20;
      reasons.push('Cumples el requisito de familia numerosa.');
    } else {
      score = 0;
      is_eligible = false;
      reasons.push('No cumples el requisito de familia numerosa.');
    }
  }

  if (eligibilityRules.exclusion_risk) {
    if (userData.exclusion_risk) {
      score += 20;
      reasons.push('Cumples el requisito de riesgo de exclusión social.');
    } else {
      score = 0;
      is_eligible = false;
      reasons.push('No cumples el requisito de riesgo de exclusión social.');
    }
  }

  if (eligibilityRules.employment_status === 'unemployed') {
    const status = (userData.employment_status || '').toLowerCase();
    if (status.includes('unemployed') || status.includes('desempleado') || status.includes('paro')) {
      score += 20;
      reasons.push('Cumples el requisito de situación de desempleo.');
    } else {
      score = 0;
      is_eligible = false;
      reasons.push('No cumples el requisito de situación de desempleo.');
    }
  }

  // Si después de evaluar todo sigue elegible, sumar puntos por match.
  // Si no, forzar a 0 aunque haya sumado algo.
  if (!is_eligible) score = 0;

  return { score, is_eligible, reasons };
}

async function recalculateMatchesForUser(userId) {
  try {
    const usersRes = await db.query(`
      SELECT u.id, s.employment_status, s.is_large_family, s.has_disability, s.is_single_parent, s.exclusion_risk 
      FROM users u
      LEFT JOIN socio_economic_data s ON u.id = s.user_id
      WHERE u.id = $1
    `, [userId]);

    if (usersRes.rows.length === 0) return;
    const user = usersRes.rows[0];

    const grantsRes = await db.query(`SELECT id, eligibility_rules FROM government_grants`);

    await db.query(`DELETE FROM grant_matches WHERE user_id = $1`, [userId]);

    for (const grant of grantsRes.rows) {
      const match = calculateGrantScore(user, grant.eligibility_rules);
      await db.query(`
        INSERT INTO grant_matches (user_id, grant_id, eligibility_score, is_eligible, reasons)
        VALUES ($1, $2, $3, $4, $5)
      `, [user.id, grant.id, match.score, match.is_eligible, JSON.stringify(match.reasons)]);
    }
  } catch (err) {
    console.error(`Error recalculando matches para el usuario ${userId}:`, err);
  }
}


// CRON JOBS (Sincronizacion de ayudas)


app.get('/api/cron/sync-grants', async (req, res) => {
  const authHeader = req.headers['authorization'];
  if (process.env.CRON_SECRET && authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ message: 'No autorizado' });
  }

  try {
    const fetchUrl = process.env.BDNS_API_URL || 'https://www.infosubvenciones.es/bdnstrans/api/convocatorias/busqueda?page=0&pageSize=100&vpd=GE';

    const response = await fetch(fetchUrl);
    if (!response.ok) {
      throw new Error(`Failed to fetch from BDNS: ${response.statusText}`);
    }

    let data = await response.json();
    // La API real de BDNS devuelve un objeto con la propiedad "content"
    if (data && data.content && Array.isArray(data.content)) {
      data = data.content;
    }

    let inserted = 0;
    let newGrantIds = [];
    for (const item of data) {
      const external_id = item.numeroConvocatoria || item.id?.toString();
      if (!external_id) continue;

      const check = await db.query('SELECT id FROM government_grants WHERE external_id = $1', [external_id]);
      if (check.rows.length > 0) continue;

      const title = item.descripcion;
      const description = item.descripcion + (item.descripcionLeng ? '\n' + item.descripcionLeng : '');

      let scope = 'National';
      if (item.nivel1 === 'LOCAL') scope = 'Local';
      else if (item.nivel1 === 'AUTONOMICA') scope = 'Regional';
      else if (item.nivel1 === 'ESTADO') scope = 'National';

      const source = item.nivel3 || item.nivel2 || 'Desconocido';
      const region_filter = item.nivel2 || null;
      const opening_date = item.fechaRecepcion || null;

      let link_info = null;
      if (item.rutaConvocatoria && item.rutaConvocatoria.startsWith('..')) {
        link_info = `https://www.pap.hacienda.gob.es/bdnstrans/GE/es${item.rutaConvocatoria.substring(2)}`;
      }

      const eligibility_rules = parseEligibilityRules(title, description);

      const resInsert = await db.query(
        `INSERT INTO government_grants (
          external_id, title, description, scope, region_filter, opening_date, source, link_info, eligibility_rules
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
        [external_id, title, description, scope, region_filter, opening_date, source, link_info, eligibility_rules ? JSON.stringify(eligibility_rules) : null]
      );

      if (resInsert.rows.length > 0) {
        newGrantIds.push({ id: resInsert.rows[0].id, rules: eligibility_rules });
        inserted++;
      }
    }

    // Actualizar Grant Matches para las nuevas convocatorias
    if (newGrantIds.length > 0) {
      try {
        const usersRes = await db.query(`
          SELECT u.id, s.employment_status, s.is_large_family, s.has_disability, s.is_single_parent, s.exclusion_risk 
          FROM users u
          LEFT JOIN socio_economic_data s ON u.id = s.user_id
        `);
        for (const user of usersRes.rows) {
          for (const grant of newGrantIds) {
            const match = calculateGrantScore(user, grant.rules);

            await db.query(`
              INSERT INTO grant_matches (user_id, grant_id, eligibility_score, is_eligible, reasons)
              VALUES ($1, $2, $3, $4, $5)
            `, [user.id, grant.id, match.score, match.is_eligible, JSON.stringify(match.reasons)]);
          }
        }
        console.log(`Se han actualizado los grant_matches para ${usersRes.rows.length} usuarios y ${newGrantIds.length} ayudas.`);
      } catch (matchErr) {
        console.error('Error actualizando grant_matches:', matchErr);
      }
    }

    res.status(200).json({ message: `Sincronización completada. ${inserted} nuevas convocatorias insertadas.` });
  } catch (err) {
    console.error('Error en cron de sincronización:', err);
    res.status(500).json({ message: 'Error en sincronización', error: err.message });
  }
});

app.listen(port, () => {
  console.log(`Server started on http://localhost:${port}`);
});
