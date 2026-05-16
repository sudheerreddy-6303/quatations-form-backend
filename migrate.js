// Run this once: node migrate.js
// Adds project_start_date and project_end_date to quotations table
require('dotenv').config();
const mysql = require('mysql2/promise');

async function migrate() {
  const conn = await mysql.createConnection({
    host:     process.env.DB_HOST,
    user:     process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port:     parseInt(process.env.DB_PORT) || 3306,
    ssl:      { rejectUnauthorized: false },
  });

  const add = async (col, def) => {
    try {
      await conn.execute(`ALTER TABLE quotations ADD COLUMN ${col} ${def}`);
      console.log(`✅ Added: ${col}`);
    } catch (e) {
      if (e.code === 'ER_DUP_FIELDNAME') console.log(`⏭  Already exists: ${col}`);
      else console.error(`❌ ${col}:`, e.message);
    }
  };

  console.log('Running migrations...\n');
  await add('project_start_date', 'DATE NULL');
  await add('project_end_date',   'DATE NULL');
  await add('discount_percent',   'DECIMAL(5,2) DEFAULT 0');
  await add('discount_amount',    'DECIMAL(12,2) DEFAULT 0');

  // Verify columns exist
  const [cols] = await conn.execute(`SHOW COLUMNS FROM quotations`);
  const names = cols.map(c => c.Field);
  console.log('\nVerification:');
  ['project_start_date','project_end_date','discount_percent','discount_amount'].forEach(c => {
    console.log(`  ${names.includes(c) ? '✅' : '❌'} ${c}`);
  });

  await conn.end();
  console.log('\nDone!');
}

migrate().catch(console.error);
