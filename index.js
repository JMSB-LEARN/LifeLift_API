const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./db');
const cors = require('cors');

const app = express();
const port = 3000;
const secretKey = 'your-secret-key';

app.use(cors());
app.use(bodyParser.json());

// Public route
app.get('/api/data', (req, res) => {
  res.json({ message: 'This is public data' });
});

// Register route
app.post('/api/register', async (req, res) => {
  const { username, email, password, first_name, surname_1, surname_2, document_number, document_type, birth_date } = req.body;

  // Validate required fields
  if (!username || !email || !password || !first_name || !surname_1 || !document_number || !birth_date) {
    return res.status(400).json({
      message: 'Missing required fields for registration'
    });
  }

  try {
    // Check if username already exists
    const usernameCheck = await db.query(
      'SELECT * FROM users WHERE username = $1',
      [username]
    );

    if (usernameCheck.rows.length > 0) {
      return res.status(409).json({
        message: 'Username already exists'
      });
    }

    // Check if email already exists
    const emailCheck = await db.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    if (emailCheck.rows.length > 0) {
      return res.status(409).json({
        message: 'Email already exists'
      });
    }

    // Hash password for password_hash column
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert new user into database
    const newUser = await db.query(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, created_at`,
      [username, email, hashedPassword]
    );

    // Insert profile
    await db.query(
      `INSERT INTO profiles (
        user_id, first_name, surname_1, surname_2, birth_date, document_number, document_type
      ) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [newUser.rows[0].id, first_name, surname_1, surname_2 || null, birth_date, document_number, document_type || 'DNI']
    );

    res.status(201).json({
      message: 'User registered successfully. Profile created.',
      user: newUser.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: 'Error registering user'
    });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
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
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    jwt.sign({ id: user.id, username: user.username }, secretKey, { expiresIn: '24h' }, (err, token) => {
      if (err) {
        return res.status(500).json({ message: 'Error generating token' });
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
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Change Password route
app.put('/api/change-password', verifyToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Current password and new password are required' });
  }

  try {
    const result = await db.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid current password' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedNewPassword, req.user.id]);

    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error changing password' });
  }
});

// Protected route
app.get('/api/protected', verifyToken, (req, res) => {
  res.json({
    message: 'This is protected data',
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

// ==========================================
// PROFILES ENDPOINTS
// ==========================================

app.get('/api/profile', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM profiles WHERE user_id = $1', [req.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Profile not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error retrieving profile' });
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
      return res.status(409).json({ message: 'Profile already exists. Use PUT to update.' });
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
    res.status(500).json({ message: 'Error creating profile' });
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
      return res.status(404).json({ message: 'Profile not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating profile' });
  }
});

// ==========================================
// SOCIO-ECONOMIC DATA ENDPOINTS
// ==========================================

app.get('/api/socio-economic', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM socio_economic_data WHERE user_id = $1', [req.user.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Socio-economic data not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error retrieving socio-economic data' });
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
      return res.status(409).json({ message: 'Data already exists. Use PUT to update.' });
    }

    const result = await db.query(
      `INSERT INTO socio_economic_data (
        user_id, education_level, employment_status, gross_annual_income, is_large_family,
        large_family_category, has_disability, disability_percentage, is_single_parent, exclusion_risk,
        dependency_grade, number_of_children
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [req.user.id, education_level, employment_status, gross_annual_income, is_large_family, large_family_category, has_disability, disability_percentage, is_single_parent, exclusion_risk, dependency_grade, number_of_children]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creating socio-economic data' });
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
      return res.status(404).json({ message: 'Socio-economic data not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating socio-economic data' });
  }
});

// ==========================================
// HOUSEMATES ENDPOINTS
// ==========================================

app.get('/api/housemates', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM housemates WHERE user_id = $1 ORDER BY id ASC', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error retrieving housemates' });
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
    res.status(500).json({ message: 'Error adding housemate' });
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
      return res.status(404).json({ message: 'Housemate not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating housemate' });
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
      return res.status(404).json({ message: 'Housemate not found' });
    }
    res.json({ message: 'Housemate deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error deleting housemate' });
  }
});

app.listen(port, () => {
  console.log(`Server started on http://localhost:${port}`);
});
