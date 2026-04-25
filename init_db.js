const db = require('./db');

async function initDb() {
    try {
        await db.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      );
    `);
        console.log('Table "users" created successfully or already exists.');
    } catch (err) {
        console.error('Error creating table:', err);
    } finally {
        // We can't easily close the pool from here without exposing it, 
        // but for a script it's fine to just exit or let the process end.
        // Ideally we'd have a pool.end() method exposed.
        process.exit();
    }
}

initDb();
