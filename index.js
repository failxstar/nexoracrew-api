// index.js - NexoraCrew Finance Backend (MongoDB + JWT)

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// ========== 1) CONNECT TO MONGODB ==========

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB Atlas'))
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
  });

// ========== 2) SCHEMAS / MODELS ==========

const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  position: { type: String, default: 'Member' },
  createdAt: { type: Date, default: Date.now },
});

const transactionSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  userName: { type: String, required: true },
  date: { type: String, required: true },
  type: { type: String, enum: ['INCOME', 'EXPENSE'], required: true },
  category: { type: String, required: true },
  amount: { type: Number, required: true },
  paymentMethod: { type: String, required: true },
  bankAccountId: { type: String },
  bankName: { type: String },
  description: { type: String, default: '' },
  attachment: { type: String },
  investmentType: { type: String, enum: ['SINGLE', 'TEAM'], default: 'SINGLE' },
  investors: [String],
  createdAt: { type: String, default: () => new Date().toISOString() },
});

const bankSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  bankName: { type: String, required: true },
  holderName: { type: String, required: true },
  cardNumber: { type: String, required: true },
  expiryDate: { type: String, required: true },
  cardType: { type: String, enum: ['DEBIT', 'CREDIT'], required: true },
});

const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);
const Bank = mongoose.model('Bank', bankSchema);

// ========== 3) HELPERS ==========

function createToken(user) {
  return jwt.sign(
    { id: user._id.toString(), name: user.name, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function sanitizeUser(user) {
  return {
    id: user._id.toString(),
    name: user.name,
    email: user.email,
    position: user.position,
    createdAt: user.createdAt.toISOString(),
  };
}

function mapTransaction(t) {
  return {
    id: t._id.toString(),
    userId: t.userId,
    userName: t.userName,
    date: t.date,
    type: t.type,
    category: t.category,
    amount: t.amount,
    paymentMethod: t.paymentMethod,
    bankAccountId: t.bankAccountId,
    bankName: t.bankName,
    description: t.description,
    attachment: t.attachment,
    investmentType: t.investmentType,
    investors: t.investors || [],
    createdAt: t.createdAt,
  };
}

function mapBank(b) {
  return {
    id: b._id.toString(),
    userId: b.userId,
    bankName: b.bankName,
    holderName: b.holderName,
    cardNumber: b.cardNumber,
    expiryDate: b.expiryDate,
    cardType: b.cardType,
  };
}

// ========== 4) AUTH MIDDLEWARE ==========

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload; // { id, name, email }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ========== 5) ROUTES ==========

// Health check
app.get('/api/ping', (req, res) => {
  res.json({ ok: true, message: 'NexoraCrew API is working 🚀' });
});

// --- Auth: Register ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, position } = req.body;

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: 'Email already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, passwordHash, position });
    const token = createToken(user);

    res.json({ user: sanitizeUser(user), token });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// --- Auth: Login ---
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Invalid credentials' });

  const token = createToken(user);
  res.json({ user: sanitizeUser(user), token });
});

// --- Get all users (Team Crew) ---
app.get('/api/users', auth, async (req, res) => {
  const users = await User.find().sort({ createdAt: -1 });
  res.json(users.map(sanitizeUser));
});

// --- Transactions ---

// Get all transactions for logged-in user
app.get('/api/transactions', auth, async (req, res) => {
  const tx = await Transaction.find({ userId: req.user.id }).sort({ date: -1 });
  res.json(tx.map(mapTransaction));
});

// Create transaction
app.post('/api/transactions', auth, async (req, res) => {
  const body = req.body;
  const tx = await Transaction.create({
    ...body,
    userId: req.user.id,
    userName: req.user.name,
  });
  res.json(mapTransaction(tx));
});

// Update transaction
app.put('/api/transactions/:id', auth, async (req, res) => {
  const { id } = req.params;
  await Transaction.updateOne(
    { _id: id, userId: req.user.id },
    { $set: req.body }
  );
  res.json({ success: true });
});

// Delete one
app.delete('/api/transactions/:id', auth, async (req, res) => {
  const { id } = req.params;
  await Transaction.deleteOne({ _id: id, userId: req.user.id });
  res.json({ success: true });
});

// Bulk delete
app.post('/api/transactions/bulk-delete', auth, async (req, res) => {
  const { ids } = req.body; // string[]
  await Transaction.deleteMany({ _id: { $in: ids }, userId: req.user.id });
  res.json({ success: true });
});

// Bulk category update
app.post('/api/transactions/bulk-category', auth, async (req, res) => {
  const { ids, category } = req.body;
  await Transaction.updateMany(
    { _id: { $in: ids }, userId: req.user.id },
    { $set: { category } }
  );
  res.json({ success: true });
});

// --- Banks / Cards ---

// Get banks for user
app.get('/api/banks', auth, async (req, res) => {
  const banks = await Bank.find({ userId: req.user.id });
  res.json(banks.map(mapBank));
});

// Create bank
app.post('/api/banks', auth, async (req, res) => {
  const bank = await Bank.create({ ...req.body, userId: req.user.id });
  res.json(mapBank(bank));
});

// Update bank
app.put('/api/banks/:id', auth, async (req, res) => {
  const { id } = req.params;
  await Bank.updateOne(
    { _id: id, userId: req.user.id },
    { $set: req.body }
  );
  res.json({ success: true });
});

// Delete bank
app.delete('/api/banks/:id', auth, async (req, res) => {
  const { id } = req.params;
  await Bank.deleteOne({ _id: id, userId: req.user.id });
  res.json({ success: true });
});

// ========== 6) START SERVER ==========

const port = process.env.PORT || 4000;
app.listen(port, () => {
  console.log(`🚀 NexoraCrew API running at http://localhost:${port}`);
});
