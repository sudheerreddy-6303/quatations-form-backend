const express    = require('express');
const cors       = require('cors');
const mysql      = require('mysql2/promise');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
require('dotenv').config();

const app = express();

// ════════════════════════════════════════════════════════════════
//  SECURITY MIDDLEWARE
// ════════════════════════════════════════════════════════════════

// 1. Security headers
app.use(helmet());

// 2. CORS — only allow your frontend origin
const ALLOWED_ORIGINS = [
  ...(process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',').map(o => o.trim()),
  'http://localhost:3001',
];
app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (mobile apps, Postman, server-side)
    if (!origin) return cb(null, true);
    // Allow all origins if wildcard is set
    if (ALLOWED_ORIGINS.includes('*')) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error(`CORS blocked: ${origin}`));
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-API-Key'],
  credentials: true,
}));

// 3. Body parser with size limits
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// 4. Rate limiting — global
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests. Please try again later.' },
});
app.use('/api/', globalLimiter);

// 5. Stricter rate limit for write operations
const writeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: { success: false, message: 'Too many write requests. Slow down.' },
});

// 6. API Key authentication middleware
const API_KEY = (process.env.API_KEY || '').trim();
const requireApiKey = (req, res, next) => {
  if (!API_KEY) return next(); // skip if not configured (dev mode)
  const key = (req.headers['x-api-key'] || '').trim();
  if (!key || key !== API_KEY) {
    return res.status(401).json({ success: false, message: 'Unauthorized: invalid or missing API key' });
  }
  next();
};

// ════════════════════════════════════════════════════════════════
//  INPUT SANITIZATION & VALIDATION HELPERS
// ════════════════════════════════════════════════════════════════

// Strip HTML tags and trim
const sanitize = (val) => {
  if (val === null || val === undefined) return '';
  return String(val).replace(/<[^>]*>/g, '').trim();
};

// Sanitize all string fields in an object recursively
const sanitizeObj = (obj) => {
  if (!obj || typeof obj !== 'object') return obj;
  if (Array.isArray(obj)) return obj.map(sanitizeObj);
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = typeof v === 'string' ? sanitize(v) : (typeof v === 'object' ? sanitizeObj(v) : v);
  }
  return out;
};

const isValidPhone = (p) => /^[0-9+\-\s]{7,15}$/.test(String(p || '').trim());
const isValidAmount = (a) => !isNaN(Number(a)) && Number(a) >= 0;
const isPositiveInt = (id) => Number.isInteger(Number(id)) && Number(id) > 0;

// Validate + sanitize quotation body — returns { errors, data } 
const validateQuotation = (body) => {
  const errors = [];
  const b = sanitizeObj(body);

  // Required fields
  if (!b.customer_name || b.customer_name.length < 2)
    errors.push('Customer name is required (min 2 characters)');
  if (!b.customer_phone || !isValidPhone(b.customer_phone))
    errors.push('Valid customer phone number is required');

  // Optional but format-validated
  if (b.customer_alt_phone && !isValidPhone(b.customer_alt_phone))
    errors.push('Alternate phone number format is invalid');
  if (b.pincode && !/^[0-9]{4,10}$/.test(b.pincode))
    errors.push('Pincode must be 4–10 digits');

  // Numeric fields
  const numFields = ['discount_percent','discount_amount','gst_percent','gst_amount','total_interior','total_ceiling','grand_total'];
  for (const f of numFields) {
    if (b[f] !== undefined && b[f] !== '' && !isValidAmount(b[f]))
      errors.push(`${f} must be a non-negative number`);
  }

  if (b.grand_total !== undefined && Number(b.grand_total) < 0)
    errors.push('Grand total cannot be negative');

  if (b.project_status && !['Booked','Unbooked'].includes(b.project_status))
    errors.push('project_status must be Booked or Unbooked');

  return { errors, data: b };
};

// Validate transaction body
const validateTransaction = (body) => {
  const errors = [];
  const b = sanitizeObj(body);

  // Allow saving with just payment_amount (scheduled) without paid_amount yet
  const hasPaid = b.paid_amount && isValidAmount(b.paid_amount) && Number(b.paid_amount) > 0;
  const hasPayment = b.payment_amount && isValidAmount(b.payment_amount) && Number(b.payment_amount) > 0;
  if (!hasPaid && !hasPayment)
    errors.push('Enter at least a Payment Amount or Paid Amount');

  return { errors, data: b };
};

// ════════════════════════════════════════════════════════════════
//  DB POOL
// ════════════════════════════════════════════════════════════════

console.log("--- Environment Variable Check ---");
console.log("DB_HOST:", process.env.DB_HOST || "NOT SET");
console.log("DB_PORT:", process.env.DB_PORT || "NOT SET");
console.log("DB_USER:", process.env.DB_USER || "NOT SET");
console.log("DB_NAME:", process.env.DB_NAME || "NOT SET");
console.log("API_KEY:", API_KEY ? "SET ✓" : "NOT SET (dev mode — no auth)");
console.log("ALLOWED_ORIGINS:", ALLOWED_ORIGINS.join(', '));
console.log("----------------------------------");

const pool = mysql.createPool({
  host:             process.env.DB_HOST,
  user:             process.env.DB_USER,
  password:         process.env.DB_PASSWORD,
  database:         process.env.DB_NAME,
  port:             parseInt(process.env.DB_PORT) || 3306,
  waitForConnections: true,
  connectionLimit:  10,
  queueLimit:       0,
  connectTimeout:   60000,
  enableKeepAlive:  true,
  keepAliveInitialDelay: 10000,
  ssl:              { rejectUnauthorized: false },
});

const ss = (v) => {
  if (v === null || v === undefined) return null;
  // If it's already a string, try to parse it first to validate JSON
  if (typeof v === 'string') {
    const trimmed = v.trim();
    if (trimmed === '') return null;
    try {
      const parsed = JSON.parse(trimmed);
      return JSON.stringify(parsed); // re-stringify ensures valid JSON
    } catch {
      // Not valid JSON — wrap as JSON string
      return JSON.stringify(trimmed);
    }
  }
  return JSON.stringify(v);
};
const sp = (v) => {
  if (v === null || v === undefined) return null;
  if (typeof v !== 'string') return v;
  try { return JSON.parse(v); } catch { return v; }
};

// ════════════════════════════════════════════════════════════════
//  DB INIT
// ════════════════════════════════════════════════════════════════
async function initDB() {
  const conn = await pool.getConnection();
  try {
    console.log("Connected to DB. Initializing...");

    await conn.execute(`
      CREATE TABLE IF NOT EXISTS quotations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        quotation_id VARCHAR(20),
        customer_name VARCHAR(255) NOT NULL,
        customer_phone VARCHAR(20) NOT NULL,
        customer_alt_phone VARCHAR(20),
        customer_designation VARCHAR(255),
        full_address TEXT,
        pincode VARCHAR(20),
        villa_number VARCHAR(100),
        site_name VARCHAR(255),
        location VARCHAR(255),
        mobile VARCHAR(20),
        project_type VARCHAR(100),
        floor_plan JSON,
        plan_2d JSON,
        plan_3d JSON,
        site_manager_name VARCHAR(255),
        site_manager_phone VARCHAR(20),
        site_manager_designation VARCHAR(255),
        site_manager_branch VARCHAR(100),
        rooms JSON,
        accessories JSON,
        ceiling_data JSON,
        discount_percent DECIMAL(5,2) DEFAULT 0,
        discount_amount DECIMAL(12,2) DEFAULT 0,
        gst_percent DECIMAL(5,2) DEFAULT 0,
        gst_amount DECIMAL(12,2) DEFAULT 0,
        total_interior DECIMAL(12,2) DEFAULT 0,
        total_ceiling DECIMAL(12,2) DEFAULT 0,
        grand_total DECIMAL(12,2) DEFAULT 0,
        tc_items JSON,
        pay_stages JSON,
        project_status VARCHAR(20) DEFAULT 'Unbooked',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    await conn.execute(`
      CREATE TABLE IF NOT EXISTS payment_stages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        quotation_id INT NOT NULL,
        stage_order INT DEFAULT 0,
        stage VARCHAR(255),
        payment_amount DECIMAL(12,2) DEFAULT 0,
        payment_date VARCHAR(50),
        paid_amount DECIMAL(12,2) DEFAULT 0,
        paid_date VARCHAR(50),
        payment_type VARCHAR(100),
        payment_details TEXT,
        received_by VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (quotation_id) REFERENCES quotations(id) ON DELETE CASCADE
      )
    `);

    await conn.execute(`
      CREATE TABLE IF NOT EXISTS payment_transactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        quotation_id INT NOT NULL,
        stage_name VARCHAR(255),
        paid_amount DECIMAL(12,2) NOT NULL DEFAULT 0,
        paid_date VARCHAR(50),
        payment_type VARCHAR(100),
        payment_details TEXT,
        received_by VARCHAR(255),
        remarks TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (quotation_id) REFERENCES quotations(id) ON DELETE CASCADE
      )
    `);

    try {
      const [cnt] = await conn.execute('SELECT COUNT(*) as c FROM quotations');
      if (cnt[0].c === 0) {
        await conn.execute('ALTER TABLE quotations AUTO_INCREMENT = 1001');
        console.log('AUTO_INCREMENT set to 1001');
      }
    } catch(e) {}

    const ac = async (tbl, col, def) => {
      try { await conn.execute(`ALTER TABLE ${tbl} ADD COLUMN ${col} ${def}`); } catch {}
    };
    // quotations migrations
    await ac('quotations', 'quotation_id',            'VARCHAR(20)');
    await ac('quotations', 'customer_alt_phone',      'VARCHAR(20)');
    await ac('quotations', 'customer_designation',    'VARCHAR(255)');
    await ac('quotations', 'full_address',            'TEXT');
    await ac('quotations', 'pincode',                 'VARCHAR(20)');
    await ac('quotations', 'villa_number',            'VARCHAR(100)');
    await ac('quotations', 'site_name',               'VARCHAR(255)');
    await ac('quotations', 'project_type',            'VARCHAR(100)');
    await ac('quotations', 'floor_plan',              'JSON');
    await ac('quotations', 'plan_2d',                 'JSON');
    await ac('quotations', 'plan_3d',                 'JSON');
    await ac('quotations', 'site_manager_name',       'VARCHAR(255)');
    await ac('quotations', 'site_manager_phone',      'VARCHAR(20)');
    await ac('quotations', 'site_manager_designation','VARCHAR(255)');
    await ac('quotations', 'site_manager_branch',     'VARCHAR(100)');
    await ac('quotations', 'discount_percent',         'DECIMAL(5,2) DEFAULT 0');
    await ac('quotations', 'discount_amount',          'DECIMAL(12,2) DEFAULT 0');
    await ac('quotations', 'gst_percent',             'DECIMAL(5,2) DEFAULT 0');
    await ac('quotations', 'gst_amount',              'DECIMAL(12,2) DEFAULT 0');
    await ac('quotations', 'tc_items',                'JSON');
    await ac('quotations', 'pay_stages',              'JSON');
    await ac('quotations', 'updated_at',              'TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
    await ac('quotations', 'project_status',           "VARCHAR(20) DEFAULT 'Unbooked'");
    // payment_stages migrations
    await ac('payment_stages', 'stage_order',      'INT DEFAULT 0');
    await ac('payment_stages', 'payment_amount',   'DECIMAL(12,2) DEFAULT 0');
    await ac('payment_stages', 'payment_date',     'VARCHAR(50)');
    await ac('payment_stages', 'paid_amount',      'DECIMAL(12,2) DEFAULT 0');
    await ac('payment_stages', 'paid_date',        'VARCHAR(50)');
    await ac('payment_stages', 'payment_type',     'VARCHAR(100)');
    await ac('payment_stages', 'payment_details',  'TEXT');
    await ac('payment_stages', 'received_by',      'VARCHAR(255)');
    await ac('payment_stages', 'updated_at',       'TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
    // payment_transactions migrations
    await ac('payment_transactions', 'stage_name',       'VARCHAR(255)');
    await ac('payment_transactions', 'payment_amount',   'DECIMAL(12,2) DEFAULT 0');
    await ac('payment_transactions', 'payment_date',     'VARCHAR(50)');
    await ac('payment_transactions', 'payment_type',     'VARCHAR(100)');
    await ac('payment_transactions', 'payment_details',  'TEXT');
    await ac('payment_transactions', 'received_by',      'VARCHAR(255)');
    await ac('payment_transactions', 'remarks',          'TEXT');
    await ac('payment_transactions', 'attachment_name',  'VARCHAR(500)');
    await ac('payment_transactions', 'attachment_data',  'LONGTEXT');

    console.log("DB initialized successfully.");
  } finally { try { conn.release(); } catch (_) {} }
}

// ════════════════════════════════════════════════════════════════
//  HELPERS
// ════════════════════════════════════════════════════════════════
async function savePaymentStages(conn, quotationId, payStages) {
  await conn.execute('DELETE FROM payment_stages WHERE quotation_id=?', [quotationId]);
  if (!Array.isArray(payStages) || !payStages.length) return;
  for (let i = 0; i < payStages.length; i++) {
    const r = sanitizeObj(payStages[i]);
    const amt  = isValidAmount(r.paymentAmount) ? parseFloat(r.paymentAmount) : 0;
    const paid = isValidAmount(r.paidAmount)     ? parseFloat(r.paidAmount)    : 0;
    await conn.execute(
      `INSERT INTO payment_stages
       (quotation_id,stage_order,stage,payment_amount,payment_date,paid_amount,paid_date,payment_type,payment_details,received_by)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [quotationId, i, r.stage||'', amt, r.paymentDate||'', paid, r.paidDate||'',
       r.paymentType||'', r.paymentDetails||'', r.receivedBy||'']
    );
  }
}

async function fetchPaymentStages(conn, quotationId) {
  const [rows] = await conn.execute(
    'SELECT * FROM payment_stages WHERE quotation_id=? ORDER BY stage_order ASC',
    [quotationId]
  );
  return rows.map(r => ({
    stage:          r.stage            || '',
    paymentAmount:  r.payment_amount   ? String(r.payment_amount) : '',
    paymentDate:    r.payment_date     || '',
    paidAmount:     r.paid_amount      ? String(r.paid_amount)    : '',
    paidDate:       r.paid_date        || '',
    paymentType:    r.payment_type     || '',
    paymentDetails: r.payment_details  || '',
    receivedBy:     r.received_by      || '',
  }));
}

// ════════════════════════════════════════════════════════════════
//  QUOTATION ROUTES
// ════════════════════════════════════════════════════════════════

/* POST — create quotation */
app.post('/api/quotations', requireApiKey, writeLimiter, async (req, res) => {
  const { errors, data: b } = validateQuotation(req.body);
  if (errors.length) return res.status(422).json({ success: false, errors });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [r] = await conn.execute(
      `INSERT INTO quotations
       (customer_name,customer_phone,customer_alt_phone,customer_designation,
        full_address,pincode,villa_number,site_name,location,mobile,
        project_type,floor_plan,plan_2d,plan_3d,
        site_manager_name,site_manager_phone,site_manager_designation,site_manager_branch,
        rooms,accessories,ceiling_data,
        gst_percent,gst_amount,total_interior,total_ceiling,grand_total,
        tc_items,pay_stages,project_status)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        b.customer_name,
        b.customer_phone || b.mobile || '',
        b.customer_alt_phone || '',
        b.customer_designation || '',
        b.full_address || '',
        b.pincode || '',
        b.villa_number || '',
        b.site_name || '',
        b.location || '',
        b.mobile || b.customer_phone || '',
        b.project_type || '',
        ss(b.floor_plan), ss(b.plan_2d), ss(b.plan_3d),
        b.site_manager_name || '',
        b.site_manager_phone || '',
        b.site_manager_designation || '',
        b.site_manager_branch || '',
        ss(b.rooms), ss(b.accessories), ss(b.ceiling_data),
        Number(b.gst_percent) || 0,
        Number(b.gst_amount)  || 0,
        Number(b.total_interior) || 0,
        Number(b.total_ceiling)  || 0,
        Number(b.grand_total)    || 0,
        ss(b.tc_items), ss(b.pay_stages),
        ['Booked','Unbooked'].includes(b.project_status) ? b.project_status : 'Unbooked'
      ]
    );

    const newId = r.insertId;
    await conn.execute('UPDATE quotations SET quotation_id=? WHERE id=?', [String(newId), newId]);
    if (Array.isArray(b.pay_stages) && b.pay_stages.length)
      await savePaymentStages(conn, newId, b.pay_stages);

    await conn.commit();
    res.status(201).json({ success: true, id: newId, quotation_id: String(newId), message: 'Quotation saved.' });
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    console.error('POST /api/quotations:', err.message);
    res.status(500).json({ success: false, message: 'Server error. Please try again.' });
  } finally { try { conn.release(); } catch (_) {} }
});

/* GET — list */
app.get('/api/quotations', requireApiKey, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT q.id, q.quotation_id, q.customer_name, q.customer_phone,
              q.location, q.mobile, q.project_type, q.site_name,
              q.site_manager_name, q.site_manager_branch, q.grand_total, q.project_status, q.created_at,
              COALESCE(SUM(pt.paid_amount),0) AS paid_total
       FROM quotations q
       LEFT JOIN payment_transactions pt ON pt.quotation_id = q.id
       GROUP BY q.id
       ORDER BY q.created_at DESC`
    );
    res.json({ success: true, data: rows });
  } catch (err) {
    console.error('GET /api/quotations:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

/* GET — single */
app.get('/api/quotations/:id', requireApiKey, async (req, res) => {
  if (!isPositiveInt(req.params.id))
    return res.status(400).json({ success: false, message: 'Invalid quotation ID.' });

  const conn = await pool.getConnection();
  try {
    const [rows] = await conn.execute('SELECT * FROM quotations WHERE id=?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ success: false, message: 'Quotation not found.' });

    const q = rows[0];
    q.rooms        = sp(q.rooms);
    q.accessories  = sp(q.accessories);
    q.ceiling_data = sp(q.ceiling_data);
    q.tc_items     = sp(q.tc_items);
    q.floor_plan   = sp(q.floor_plan);
    q.plan_2d      = sp(q.plan_2d);
    q.plan_3d      = sp(q.plan_3d);

    const stages = await fetchPaymentStages(conn, q.id);
    q.pay_stages = stages.length > 0 ? stages : sp(q.pay_stages);

    res.json({ success: true, data: q });
  } catch (err) {
    console.error('GET /api/quotations/:id:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  } finally { try { conn.release(); } catch (_) {} }
});

/* PUT — update */
app.put('/api/quotations/:id', requireApiKey, writeLimiter, async (req, res) => {
  if (!isPositiveInt(req.params.id))
    return res.status(400).json({ success: false, message: 'Invalid quotation ID.' });

  const { errors, data: b } = validateQuotation(req.body);
  if (errors.length) return res.status(422).json({ success: false, errors });

  const conn = await pool.getConnection();
  try {
    // Verify quotation exists
    const [exists] = await conn.execute('SELECT id FROM quotations WHERE id=?', [req.params.id]);
    if (!exists.length) return res.status(404).json({ success: false, message: 'Quotation not found.' });

    await conn.beginTransaction();

    await conn.execute(
      `UPDATE quotations SET
        customer_name=?,customer_phone=?,customer_alt_phone=?,customer_designation=?,
        full_address=?,pincode=?,villa_number=?,site_name=?,location=?,mobile=?,
        project_type=?,floor_plan=?,plan_2d=?,plan_3d=?,
        site_manager_name=?,site_manager_phone=?,site_manager_designation=?,site_manager_branch=?,
        rooms=?,accessories=?,ceiling_data=?,
        discount_percent=?,discount_amount=?,
        gst_percent=?,gst_amount=?,total_interior=?,total_ceiling=?,grand_total=?,
        tc_items=?,pay_stages=?,project_status=?
       WHERE id=?`,
      [
        b.customer_name,
        b.customer_phone || b.mobile || '',
        b.customer_alt_phone || '',
        b.customer_designation || '',
        b.full_address || '',
        b.pincode || '',
        b.villa_number || '',
        b.site_name || '',
        b.location || '',
        b.mobile || b.customer_phone || '',
        b.project_type || '',
        ss(b.floor_plan), ss(b.plan_2d), ss(b.plan_3d),
        b.site_manager_name || '',
        b.site_manager_phone || '',
        b.site_manager_designation || '',
        b.site_manager_branch || '',
        ss(b.rooms), ss(b.accessories), ss(b.ceiling_data),
        Number(b.discount_percent) || 0,
        Number(b.discount_amount)  || 0,
        Number(b.gst_percent) || 0,
        Number(b.gst_amount)  || 0,
        Number(b.total_interior) || 0,
        Number(b.total_ceiling)  || 0,
        Number(b.grand_total)    || 0,
        ss(b.tc_items), ss(b.pay_stages),
        ['Booked','Unbooked'].includes(b.project_status) ? b.project_status : 'Unbooked',
        req.params.id
      ]
    );

    if (Array.isArray(b.pay_stages))
      await savePaymentStages(conn, req.params.id, b.pay_stages);

    await conn.commit();
    res.json({ success: true, message: 'Quotation updated.' });
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    console.error('PUT /api/quotations/:id:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  } finally { try { conn.release(); } catch (_) {} }
});

/* PATCH — update status only */
app.patch('/api/quotations/:id/status', requireApiKey, async (req, res) => {
  if (!isPositiveInt(req.params.id))
    return res.status(400).json({ success: false, message: 'Invalid quotation ID.' });

  const { project_status } = req.body;
  if (!['Booked','Unbooked'].includes(project_status))
    return res.status(422).json({ success: false, message: 'project_status must be Booked or Unbooked' });

  try {
    const [r] = await pool.execute(
      'UPDATE quotations SET project_status=? WHERE id=?',
      [project_status, req.params.id]
    );
    if (r.affectedRows === 0)
      return res.status(404).json({ success: false, message: 'Quotation not found.' });
    res.json({ success: true, message: `Status updated to ${project_status}` });
  } catch (err) {
    console.error('PATCH /status:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

/* PUT — status only (simple, no full validation) */
app.put('/api/quotations/:id/status-only', requireApiKey, async (req, res) => {
  if (!isPositiveInt(req.params.id))
    return res.status(400).json({ success: false, message: 'Invalid quotation ID.' });

  const status = sanitize(req.body.project_status || '');
  if (!['Booked','Unbooked'].includes(status))
    return res.status(422).json({ success: false, message: 'project_status must be Booked or Unbooked' });

  try {
    const [r] = await pool.execute(
      'UPDATE quotations SET project_status=? WHERE id=?',
      [status, req.params.id]
    );
    if (r.affectedRows === 0)
      return res.status(404).json({ success: false, message: 'Quotation not found.' });
    res.json({ success: true, message: `Status updated to ${status}` });
  } catch (err) {
    console.error('PUT /status-only:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

/* DELETE */
app.delete('/api/quotations/:id', requireApiKey, writeLimiter, async (req, res) => {
  if (!isPositiveInt(req.params.id))
    return res.status(400).json({ success: false, message: 'Invalid quotation ID.' });
  try {
    const [r] = await pool.execute('DELETE FROM quotations WHERE id=?', [req.params.id]);
    if (r.affectedRows === 0)
      return res.status(404).json({ success: false, message: 'Quotation not found.' });
    res.json({ success: true, message: 'Quotation deleted.' });
  } catch (err) {
    console.error('DELETE /api/quotations:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ════════════════════════════════════════════════════════════════
//  PAYMENT STAGES
// ════════════════════════════════════════════════════════════════

app.get('/api/quotations/:id/payment-stages', requireApiKey, async (req, res) => {
  if (!isPositiveInt(req.params.id))
    return res.status(400).json({ success: false, message: 'Invalid ID.' });
  const conn = await pool.getConnection();
  try {
    const stages = await fetchPaymentStages(conn, req.params.id);
    res.json({ success: true, data: stages });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  } finally { try { conn.release(); } catch (_) {} }
});

app.put('/api/quotations/:id/payment-stages', requireApiKey, writeLimiter, async (req, res) => {
  if (!isPositiveInt(req.params.id))
    return res.status(400).json({ success: false, message: 'Invalid ID.' });
  const conn = await pool.getConnection();
  try {
    const [exists] = await conn.execute('SELECT id FROM quotations WHERE id=?', [req.params.id]);
    if (!exists.length) return res.status(404).json({ success: false, message: 'Quotation not found.' });

    await conn.beginTransaction();
    const { pay_stages } = req.body;
    await savePaymentStages(conn, req.params.id, pay_stages || []);
    await conn.execute('UPDATE quotations SET pay_stages=? WHERE id=?', [ss(pay_stages), req.params.id]);
    await conn.commit();
    res.json({ success: true, message: 'Payment stages updated.' });
  } catch (err) {
    try { await conn.rollback(); } catch (_) {}
    res.status(500).json({ success: false, message: 'Server error.' });
  } finally { try { conn.release(); } catch (_) {} }
});

// ════════════════════════════════════════════════════════════════
//  PAYMENT TRANSACTIONS
// ════════════════════════════════════════════════════════════════

/* GET all transactions for a quotation */
app.get('/api/quotations/:id/transactions', requireApiKey, async (req, res) => {
  if (!isPositiveInt(req.params.id))
    return res.status(400).json({ success: false, message: 'Invalid ID.' });
  try {
    // Verify quotation exists before returning transactions
    const [exists] = await pool.execute('SELECT id FROM quotations WHERE id=?', [req.params.id]);
    if (!exists.length) return res.status(404).json({ success: false, message: 'Quotation not found.' });

    const [rows] = await pool.execute(
      'SELECT * FROM payment_transactions WHERE quotation_id=? ORDER BY created_at ASC',
      [req.params.id]
    );
    res.json({ success: true, data: rows });
  } catch (err) {
    console.error('GET /transactions:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

/* POST — add transaction */
app.post('/api/quotations/:id/transactions', requireApiKey, writeLimiter, async (req, res) => {
  if (!isPositiveInt(req.params.id))
    return res.status(400).json({ success: false, message: 'Invalid ID.' });

  const { errors, data: b } = validateTransaction(req.body);
  if (errors.length) return res.status(422).json({ success: false, errors });

  try {
    // Verify quotation exists — prevents orphan transactions
    const [exists] = await pool.execute('SELECT id,grand_total FROM quotations WHERE id=?', [req.params.id]);
    if (!exists.length) return res.status(404).json({ success: false, message: 'Quotation not found.' });

    // Prevent overpayment (only when paid_amount > 0)
    const paidAmt = parseFloat(b.paid_amount) || 0;
    if (paidAmt > 0) {
      const [totRow] = await pool.execute(
        'SELECT COALESCE(SUM(paid_amount),0) as total FROM payment_transactions WHERE quotation_id=?',
        [req.params.id]
      );
      const alreadyPaid = Number(totRow[0].total);
      const grandTotal  = Number(exists[0].grand_total);
      const newTotal    = alreadyPaid + paidAmt;
      if (grandTotal > 0 && newTotal > grandTotal * 1.01) {
        return res.status(422).json({
          success: false,
          message: `Payment of ₹${paidAmt} would exceed grand total ₹${grandTotal}. Already paid: ₹${alreadyPaid}.`
        });
      }
    }

    const [r] = await pool.execute(
      `INSERT INTO payment_transactions
       (quotation_id,stage_name,payment_amount,payment_date,paid_amount,paid_date,payment_type,payment_details,received_by,remarks,attachment_name,attachment_data)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      [req.params.id, b.stage_name||'',
       parseFloat(b.payment_amount)||0, b.payment_date||'',
       parseFloat(b.paid_amount)||0, b.paid_date||'',
       b.payment_type||'', b.payment_details||'', b.received_by||'', b.remarks||'',
       b.attachment_name||null, b.attachment_data||null]
    );
    const [rows] = await pool.execute('SELECT * FROM payment_transactions WHERE id=?', [r.insertId]);
    res.status(201).json({ success: true, data: rows[0], message: 'Payment recorded.' });
  } catch (err) {
    console.error('POST /transactions:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

/* PUT — update transaction */
app.put('/api/transactions/:txnId', requireApiKey, writeLimiter, async (req, res) => {
  if (!isPositiveInt(req.params.txnId))
    return res.status(400).json({ success: false, message: 'Invalid transaction ID.' });

  const { errors, data: b } = validateTransaction(req.body);
  if (errors.length) return res.status(422).json({ success: false, errors });

  try {
    const [exists] = await pool.execute('SELECT id FROM payment_transactions WHERE id=?', [req.params.txnId]);
    if (!exists.length) return res.status(404).json({ success: false, message: 'Transaction not found.' });

    await pool.execute(
      `UPDATE payment_transactions SET
       stage_name=?,payment_amount=?,payment_date=?,paid_amount=?,paid_date=?,payment_type=?,payment_details=?,received_by=?,remarks=?,attachment_name=?,attachment_data=?
       WHERE id=?`,
      [b.stage_name||'', parseFloat(b.payment_amount)||0, b.payment_date||'',
       parseFloat(b.paid_amount)||0, b.paid_date||'',
       b.payment_type||'', b.payment_details||'', b.received_by||'', b.remarks||'',
       b.attachment_name||null, b.attachment_data||null,
       req.params.txnId]
    );
    const [rows] = await pool.execute('SELECT * FROM payment_transactions WHERE id=?', [req.params.txnId]);
    res.json({ success: true, data: rows[0], message: 'Transaction updated.' });
  } catch (err) {
    console.error('PUT /transactions:', err.message);
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

/* DELETE — transaction */
app.delete('/api/transactions/:txnId', requireApiKey, writeLimiter, async (req, res) => {
  if (!isPositiveInt(req.params.txnId))
    return res.status(400).json({ success: false, message: 'Invalid transaction ID.' });
  try {
    const [r] = await pool.execute('DELETE FROM payment_transactions WHERE id=?', [req.params.txnId]);
    if (r.affectedRows === 0)
      return res.status(404).json({ success: false, message: 'Transaction not found.' });
    res.json({ success: true, message: 'Transaction deleted.' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error.' });
  }
});

// ════════════════════════════════════════════════════════════════
//  GLOBAL ERROR HANDLER
// ════════════════════════════════════════════════════════════════
app.use((err, req, res, next) => {
  if (err.message && err.message.startsWith('CORS blocked')) {
    return res.status(403).json({ success: false, message: err.message });
  }
  console.error('Unhandled error:', err);
  res.status(500).json({ success: false, message: 'Internal server error.' });
});

app.get('/', (req, res) => res.json({ status: 'ok', service: 'Deeraj Interiors API' }));

// ════════════════════════════════════════════════════════════════
//  START
// ════════════════════════════════════════════════════════════════
// Prevent server crash on unhandled errors
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception (server kept alive):', err.message);
});
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection (server kept alive):', reason);
});

const PORT = process.env.PORT || 5001;
(async () => {
  if (!process.env.DB_HOST) { console.error("DB_HOST not set"); process.exit(1); }
  try {
    await initDB();
    app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
  } catch (err) {
    console.error("Startup failed:", err);
    process.exit(1);
  }
})();