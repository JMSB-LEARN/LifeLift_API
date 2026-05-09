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
app.use(bodyParser.json({ limit: '20mb' }));
app.use(bodyParser.urlencoded({ limit: '20mb', extended: true }));

// Ensure document_pdf column exists
(async () => {
  try {
    await db.query('ALTER TABLE user_applications ADD COLUMN IF NOT EXISTS document_pdf BYTEA');
    console.log('Ensured document_pdf column exists in user_applications');
  } catch (err) {
    console.error('Migration error: could not add document_pdf column', err);
  }
})();

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

    await recalculateMatchesForUser(newUser.rows[0].id);

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

    await recalculateMatchesForUser(req.user.id);

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

    await recalculateMatchesForUser(req.user.id);

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

// ==========================================
// GRANTS ENDPOINTS
// ==========================================

app.get('/api/grants', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM government_grants ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error retrieving grants' });
  }
});

app.get('/api/grants/:id', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM government_grants WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Grant not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error retrieving grant' });
  }
});

// ==========================================
// APPLICATIONS ENDPOINTS
// ==========================================

app.get('/api/applications', verifyToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM user_applications WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error retrieving applications' });
  }
});

app.post('/api/applications', verifyToken, async (req, res) => {
  const { grant_id, status, amount_granted, application_ref_number, notes, applied_at } = req.body;
  
  if (!grant_id) {
    return res.status(400).json({ message: 'grant_id is required' });
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
    res.status(500).json({ message: 'Error creating application' });
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
      return res.status(404).json({ message: 'Application not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating application' });
  }
});

// Upload PDF document
app.put('/api/applications/:id/document', verifyToken, async (req, res) => {
  const applicationId = req.params.id;
  const { document_pdf } = req.body;

  if (!document_pdf) {
    return res.status(400).json({ message: 'document_pdf is required' });
  }

  try {
    const check = await db.query('SELECT id FROM user_applications WHERE id = $1 AND user_id = $2', [applicationId, req.user.id]);
    if (check.rows.length === 0) {
      return res.status(404).json({ message: 'Application not found' });
    }

    const base64Data = document_pdf.replace(/^data:application\/pdf;base64,/, "");
    const buffer = Buffer.from(base64Data, 'base64');

    await db.query(
      'UPDATE user_applications SET document_pdf = $1 WHERE id = $2',
      [buffer, applicationId]
    );

    res.json({ message: 'Document uploaded successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error uploading document' });
  }
});

// Retrieve PDF document
app.get('/api/applications/:id/document', verifyToken, async (req, res) => {
  const applicationId = req.params.id;

  try {
    const result = await db.query('SELECT document_pdf FROM user_applications WHERE id = $1 AND user_id = $2', [applicationId, req.user.id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Application not found' });
    }

    const doc = result.rows[0].document_pdf;
    if (!doc) {
      return res.status(404).json({ message: 'No document attached' });
    }

    const base64 = doc.toString('base64');
    res.json({ document_pdf: `data:application/pdf;base64,${base64}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error retrieving document' });
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
      return res.status(404).json({ message: 'Application not found' });
    }
    res.json({ message: 'Application deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error deleting application' });
  }
});

// ==========================================
// GRANT MATCHES ENDPOINTS
// ==========================================

app.get('/api/grant-matches', verifyToken, async (req, res) => {
  try {
    // Join with government_grants to get grant details
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
    res.status(500).json({ message: 'Error retrieving grant matches' });
  }
});

app.post('/api/grant-matches', verifyToken, async (req, res) => {
  const { grant_id, eligibility_score, is_eligible, reasons } = req.body;
  
  if (!grant_id) {
    return res.status(400).json({ message: 'grant_id is required' });
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
    res.status(500).json({ message: 'Error creating grant match' });
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
      return res.status(404).json({ message: 'Grant match not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating grant match' });
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
      return res.status(404).json({ message: 'Grant match not found' });
    }
    res.json({ message: 'Grant match deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error deleting grant match' });
  }
});

// ==========================================
// UTILITY FUNCTIONS
// ==========================================

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

// ==========================================
// CRON JOBS ENDPOINTS
// ==========================================

app.get('/api/cron/sync-grants', async (req, res) => {
  // Vercel cron security check (optional but recommended)
  const authHeader = req.headers['authorization'];
  if (process.env.CRON_SECRET && authHeader !== `Bearer ${process.env.CRON_SECRET}`) {
    return res.status(401).json({ message: 'Unauthorized' });
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
