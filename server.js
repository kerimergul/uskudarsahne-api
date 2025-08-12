const path = require('path');
const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const multer = require('multer');
const sharp = require('sharp');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const mongoose = require('mongoose');
require('dotenv').config();

// ---------- ENV ----------
const PORT = process.env.PORT || 4000;
const MONGODB_URI = process.env.MONGODB_URI;
const SESSION_SECRET = process.env.SESSION_SECRET || 'devsecret';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'password';
const BUNNY_STORAGE_NAME = process.env.BUNNY_STORAGE_NAME;
const BUNNY_STORAGE_KEY = process.env.BUNNY_STORAGE_KEY;
const BUNNY_STORAGE_HOST = process.env.BUNNY_STORAGE_HOST || 'https://storage.bunnycdn.com';
const BUNNY_CDN_BASE = process.env.BUNNY_CDN_BASE; // e.g. https://cdn.uskudarsahne.com

if (!MONGODB_URI) throw new Error('MONGODB_URI missing');
if (!BUNNY_STORAGE_NAME || !BUNNY_STORAGE_KEY || !BUNNY_CDN_BASE) {
  console.warn('[WARN] Bunny CDN env vars missing; upload routes will fail until set.');
}

// ---------- DB ----------
mongoose.set('strictQuery', true);
mongoose.connect(MONGODB_URI).then(() => {
  console.log('MongoDB connected');
}).catch(err => {
  console.error('MongoDB connection error:', err.message);
  process.exit(1);
});

// Schemas
const { Schema, Types } = mongoose;

const CategorySchema = new Schema({
  name: { type: String, required: true, trim: true },
  kind: { type: String, enum: ['food','drink'], required: true }, // "yemek mi içecek mi"
  images: {
    w640: { type: String },
    w1024: { type: String }
  }
}, { timestamps: { createdAt: 'createdAt', updatedAt: 'updatedAt' } });

// Unique by name (case-insensitive): Atlas'ta oluşturduğun index ile uyumlu.
CategorySchema.index({ name: 1 }, { unique: true, collation: { locale: 'tr', strength: 2 } });

const ProductSchema = new Schema({
  name: { type: String, required: true, trim: true },
  description: { type: String, default: '' },
  price: { type: Schema.Types.Decimal128, required: true },
  images: {
    w640: { type: String },
    w1024: { type: String }
  },
  categoryId: { type: Schema.Types.ObjectId, ref: 'Category', required: true }
}, { timestamps: { createdAt: 'createdAt', updatedAt: 'updatedAt' } });

// Örnek indexler (Atlas'ta zaten oluşturduysan tekrarlamaz):
ProductSchema.index({ categoryId: 1, name: 1 }); // idx_products_category_name
ProductSchema.index({ name: 'text', description: 'text' }, { default_language: 'turkish' }); // idx_products_text_tr

const Category = mongoose.model('Category', CategorySchema, 'categories');
const Product  = mongoose.model('Product',  ProductSchema,  'products');

// ---------- APP ----------
const app = express();

app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(morgan('dev'));
app.set('trust proxy', 1);

app.use(session({
  name: 'sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false, // prod: true (HTTPS)
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 8 // 8h
  }
}));

// ---------- Auth (çok basit, tokensiz) ----------
const loginLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 20 });

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    req.session.user = { username };
    return res.json({ ok: true, username });
  }
  return res.status(401).json({ ok: false, error: 'Invalid credentials' });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.json({ ok: true });
  });
});

app.get('/api/auth/me', (req, res) => {
  res.json({ loggedIn: !!req.session.user, user: req.session.user || null });
});

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ---------- Helpers ----------
function toDecimal128(val) {
  if (val == null) return undefined;
  const s = typeof val === 'number' ? val.toFixed(2) : String(val);
  return mongoose.Types.Decimal128.fromString(s);
}

async function bunnyPut(pathInZone, buffer, contentType) {
  const url = `${BUNNY_STORAGE_HOST}/${BUNNY_STORAGE_NAME}/${pathInZone}`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      'AccessKey': BUNNY_STORAGE_KEY,
      'Content-Type': contentType
    },
    body: buffer
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Bunny upload failed ${res.status}: ${text}`);
  }
  return `${BUNNY_CDN_BASE}/${pathInZone}`;
}

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });

async function processAndUpload(fileBuffer, basePath, baseNameNoExt, vTag) {
  // 2 boyut (webp). İstersen AVIF de ekleyebilirsin.
  const w640  = await sharp(fileBuffer).resize({ width: 640 }).webp({ quality: 82 }).toBuffer();
  const w1024 = await sharp(fileBuffer).resize({ width: 1024 }).webp({ quality: 80 }).toBuffer();

  const p640  = `${basePath}/${baseNameNoExt}_w640_${vTag}.webp`;
  const p1024 = `${basePath}/${baseNameNoExt}_w1024_${vTag}.webp`;

  const url640  = await bunnyPut(p640,  w640,  'image/webp');
  const url1024 = await bunnyPut(p1024, w1024, 'image/webp');

  return { w640: url640, w1024: url1024 };
}

// ---------- Public API ----------
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.get('/api/categories', async (req, res) => {
  const categories = await Category.find().sort({ createdAt: 1 }).lean();
  res.json(categories);
});

app.get('/api/products', async (req, res) => {
  const { categoryId, q, limit = 100 } = req.query;
  const filter = {};
  if (categoryId && Types.ObjectId.isValid(categoryId)) filter.categoryId = new Types.ObjectId(categoryId);
  if (q) filter.$text = { $search: String(q) };
  const items = await Product.find(filter).limit(Math.min(Number(limit) || 100, 500)).lean();
  res.json(items);
});

app.get('/api/products/:id', async (req, res) => {
  const { id } = req.params;
  if (!Types.ObjectId.isValid(id)) return res.status(400).json({ error: 'bad id' });
  const prod = await Product.findById(id).lean();
  if (!prod) return res.status(404).json({ error: 'not found' });
  res.json(prod);
});

// ---------- Admin: Categories CRUD ----------
app.post('/api/admin/categories', requireAuth, async (req, res) => {
  try {
    const { name, kind } = req.body;
    const doc = await Category.create({ name, kind });
    res.status(201).json(doc);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/admin/categories/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, kind, images } = req.body;
    const update = {};
    if (name != null) update.name = name;
    if (kind != null) update.kind = kind;
    if (images && typeof images === 'object') update.images = images;
    const doc = await Category.findByIdAndUpdate(id, update, { new: true });
    if (!doc) return res.status(404).json({ error: 'not found' });
    res.json(doc);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/admin/categories/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const doc = await Category.findByIdAndDelete(id);
    if (!doc) return res.status(404).json({ error: 'not found' });
    // Not: İsteğe bağlı olarak bu kategoriye bağlı ürünleri de silmek isteyebilirsin.
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ---------- Admin: Products CRUD ----------
app.post('/api/admin/products', requireAuth, async (req, res) => {
  try {
    const { name, description, price, categoryId } = req.body;
    if (!Types.ObjectId.isValid(categoryId)) return res.status(400).json({ error: 'bad categoryId' });
    const doc = await Product.create({
      name,
      description: description || '',
      price: toDecimal128(price),
      categoryId
    });
    res.status(201).json(doc);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/admin/products/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, price, categoryId, images } = req.body;
    const update = {};
    if (name != null) update.name = name;
    if (description != null) update.description = description;
    if (price != null) update.price = toDecimal128(price);
    if (categoryId != null) {
      if (!Types.ObjectId.isValid(categoryId)) return res.status(400).json({ error: 'bad categoryId' });
      update.categoryId = categoryId;
    }
    if (images && typeof images === 'object') update.images = images;
    const doc = await Product.findByIdAndUpdate(id, update, { new: true });
    if (!doc) return res.status(404).json({ error: 'not found' });
    res.json(doc);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/admin/products/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const doc = await Product.findByIdAndDelete(id);
    if (!doc) return res.status(404).json({ error: 'not found' });
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ---------- Admin: Upload to Bunny (category/product) ----------
// Route: POST /api/admin/upload/:type/:id
// type: categories | products
// body: multipart/form-data { file }
// action: üretilen URL'leri döner ve dokümana yazar (images.w640, images.w1024)
app.post('/api/admin/upload/:type/:id', requireAuth, upload.single('file'), async (req, res) => {
  try {
    const { type, id } = req.params;
    if (!req.file) return res.status(400).json({ error: 'file missing' });
    if (!['categories','products'].includes(type)) return res.status(400).json({ error: 'bad type' });
    if (!Types.ObjectId.isValid(id)) return res.status(400).json({ error: 'bad id' });

    // version tag: timestamp
    const v = `v${Date.now()}`;

    const basePath = `${type}/${id}`; // categories/<id> | products/<id>
    const baseName = type === 'categories' ? 'cover' : 'main';

    const urls = await processAndUpload(req.file.buffer, basePath, baseName, v);

    // DB'ye yaz
    let doc;
    if (type === 'categories') {
      doc = await Category.findByIdAndUpdate(id, { images: urls }, { new: true });
    } else {
      doc = await Product.findByIdAndUpdate(id, { images: urls }, { new: true });
    }
    if (!doc) return res.status(404).json({ error: 'doc not found' });

    res.json({ ok: true, images: urls, doc });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});
