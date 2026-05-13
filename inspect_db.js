const db = require('./db');

async function inspect() {
    try {
        const res = await db.query(`
      SELECT column_name, data_type 
      FROM information_schema.columns 
      WHERE table_name = 'users';
    `);
        console.log('Columns in users table:', res.rows);
    } catch (err) {
        console.error('Error inspecting table:', err);
    } finally {
        setTimeout(() => process.exit(), 1000);
    }
}

inspect();
