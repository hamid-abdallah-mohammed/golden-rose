
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!process.env.DATABASE_URL || !JWT_SECRET) {
  console.error("DATABASE_URL and JWT_SECRET are required.");
  process.exit(1);
}

// =============================
// General
// =============================

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", store: "Golden Rose" });
});

// =============================
// Authentication
// =============================

function authenticateToken(req, res, next) {
  const header = req.headers.authorization;
  const token = header && header.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "يرجى تسجيل الدخول" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "انتهت الجلسة أو الرمز غير صالح" });
    }

    req.user = user;
    next();
  });
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "غير مسموح لك بالدخول" });
  }

  next();
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      name: user.name,
      email: user.email || null,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// Customer registration
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, phone, email, password } = req.body;

    if (!name || !email || !password || password.length < 6) {
      return res.status(400).json({
        message: "أدخل الاسم والبريد وكلمة مرور لا تقل عن 6 أحرف"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (name, phone, email, password, role)
       VALUES ($1, $2, $3, $4, 'customer')
       RETURNING id, name, phone, email, role`,
      [name.trim(), phone || null, email.trim().toLowerCase(), hashedPassword]
    );

    const user = result.rows[0];

    res.status(201).json({
      message: "تم إنشاء الحساب بنجاح",
      token: createToken(user),
      user
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ message: "البريد الإلكتروني مستخدم مسبقاً" });
    }

    console.error(error);
    res.status(500).json({ message: "حدث خطأ أثناء إنشاء الحساب" });
  }
});

// Customer login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      `SELECT * FROM users
       WHERE email = $1 AND role = 'customer'`,
      [String(email || "").trim().toLowerCase()]
    );

    if (!result.rows.length) {
      return res.status(401).json({ message: "البريد أو كلمة المرور غير صحيحة" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password || "", user.password);

    if (!valid) {
      return res.status(401).json({ message: "البريد أو كلمة المرور غير صحيحة" });
    }

    res.json({
      message: "تم تسجيل الدخول بنجاح",
      token: createToken(user),
      user: {
        id: user.id,
        name: user.name,
        phone: user.phone,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "حدث خطأ أثناء تسجيل الدخول" });
  }
});

// Admin login - credentials are stored in Render environment
app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;

  if (
    !process.env.ADMIN_USERNAME ||
    !process.env.ADMIN_PASSWORD ||
    username !== process.env.ADMIN_USERNAME ||
    password !== process.env.ADMIN_PASSWORD
  ) {
    return res.status(401).json({ message: "بيانات الأدمن غير صحيحة" });
  }

  const user = {
    id: 0,
    name: "مدير المتجر",
    role: "admin"
  };

  res.json({
    message: "تم دخول الأدمن بنجاح",
    token: createToken(user),
    user
  });
});

// Current logged-in user
app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    if (req.user.role === "admin") {
      return res.json({
        user: {
          id: 0,
          name: "مدير المتجر",
          role: "admin"
        }
      });
    }

    const result = await pool.query(
      `SELECT id, name, phone, email, role
       FROM users WHERE id = $1 AND role = 'customer'`,
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(401).json({ message: "الحساب غير موجود" });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "حدث خطأ" });
  }
});

// Logout: the frontend clears its stored token
app.post("/api/auth/logout", authenticateToken, (req, res) => {
  res.json({ message: "تم تسجيل الخروج بنجاح" });
});

// =============================
// Perfumes
// =============================

app.get("/api/perfumes", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM perfumes ORDER BY created_at DESC"
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "تعذر تحميل العطور" });
  }
});

// Single perfume
app.get("/api/perfumes/:id", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM perfumes WHERE id = $1",
      [req.params.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ message: "العطر غير موجود" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: "حدث خطأ" });
  }
});

// Add perfume
app.post("/api/perfumes", authenticateToken, adminOnly, async (req, res) => {
  try {
    const { name, brand, category, price, image, description, stock } = req.body;

    if (!name || !category || !Number.isFinite(Number(price)) ||
        Number(price) < 0 || !Number.isInteger(Number(stock)) ||
        Number(stock) < 0) {
      return res.status(400).json({ message: "بيانات العطر غير مكتملة أو غير صحيحة" });
    }

    const result = await pool.query(
      `INSERT INTO perfumes
       (name, brand, category, price, image, description, stock)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [name, brand || null, category, price, image || null,
       description || null, stock]
    );

    res.status(201).json({
      message: "تمت إضافة العطر",
      perfume: result.rows[0]
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "تعذرت إضافة العطر" });
  }
});

// Update perfume
app.put("/api/perfumes/:id", authenticateToken, adminOnly, async (req, res) => {
  try {
    const { name, brand, category, price, image, description, stock } = req.body;

    const result = await pool.query(
      `UPDATE perfumes SET
       name=$1, brand=$2, category=$3, price=$4,
       image=$5, description=$6, stock=$7
       WHERE id=$8 RETURNING *`,
      [name, brand || null, category, price, image || null,
       description || null, stock, req.params.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ message: "العطر غير موجود" });
    }

    res.json({ message: "تم تحديث العطر", perfume: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "تعذر تحديث العطر" });
  }
});

// Delete perfume
app.delete("/api/perfumes/:id", authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM perfumes WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ message: "العطر غير موجود" });
    }

    res.json({ message: "تم حذف العطر" });
  } catch (error) {
    if (error.code === "23503") {
      return res.status(409).json({
        message: "لا يمكن حذف هذا العطر لأنه مرتبط بطلب سابق"
      });
    }

    res.status(500).json({ message: "تعذر حذف العطر" });
  }
});

// =============================
// Shopping Cart
// =============================

app.get("/api/cart", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "customer") {
      return res.status(403).json({ message: "هذه الخدمة للعملاء فقط" });
    }

    const result = await pool.query(
      `SELECT c.id, c.perfume_id, c.quantity,
              p.name, p.brand, p.price, p.image, p.stock
       FROM cart_items c
       JOIN perfumes p ON p.id = c.perfume_id
       WHERE c.user_id = $1 ORDER BY c.created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "تعذر تحميل السلة" });
  }
});

// Add to cart
app.post("/api/cart", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "customer") {
      return res.status(403).json({ message: "هذه الخدمة للعملاء فقط" });
    }

    const { perfume_id, quantity = 1 } = req.body;
    const qty = Number(quantity);

    if (!Number.isInteger(qty) || qty < 1) {
      return res.status(400).json({ message: "الكمية غير صحيحة" });
    }

    const perfume = await pool.query(
      "SELECT id, stock FROM perfumes WHERE id=$1",
      [perfume_id]
    );

    if (!perfume.rows.length) {
      return res.status(404).json({ message: "العطر غير موجود" });
    }

    const current = await pool.query(
      "SELECT quantity FROM cart_items WHERE user_id=$1 AND perfume_id=$2",
      [req.user.id, perfume_id]
    );

    const totalQty = qty + (current.rows[0]?.quantity || 0);

    if (totalQty > perfume.rows[0].stock) {
      return res.status(400).json({ message: "الكمية المطلوبة غير متوفرة" });
    }

    const result = await pool.query(
      `INSERT INTO cart_items (user_id, perfume_id, quantity)
       VALUES ($1,$2,$3)
       ON CONFLICT (user_id, perfume_id)
       DO UPDATE SET quantity = cart_items.quantity + EXCLUDED.quantity
       RETURNING *`,
      [req.user.id, perfume_id, qty]
    );

    res.json({ message: "تمت إضافة العطر للسلة", item: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "تعذرت إضافة العطر" });
  }
});

// Update cart quantity
app.patch("/api/cart/:id", authenticateToken, async (req, res) => {
  try {
    const qty = Number(req.body.quantity);

    if (req.user.role !== "customer") {
      return res.status(403).json({ message: "هذه الخدمة للعملاء فقط" });
    }

    if (!Number.isInteger(qty) || qty < 1) {
      return res.status(400).json({ message: "الكمية غير صحيحة" });
    }

    const result = await pool.query(
      `UPDATE cart_items c SET quantity=$1
       FROM perfumes p
       WHERE c.id=$2 AND c.user_id=$3
       AND p.id=c.perfume_id AND p.stock >= $1
       RETURNING c.*`,
      [qty, req.params.id, req.user.id]
    );

    if (!result.rows.length) {
      return res.status(400).json({ message: "الكمية غير متوفرة أو العنصر غير موجود" });
    }

    res.json({ message: "تم تحديث الكمية", item: result.rows[0] });
  } catch (error) {
    res.status(500).json({ message: "حدث خطأ" });
  }
});

// Remove cart item
app.delete("/api/cart/:id", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "customer") {
      return res.status(403).json({ message: "هذه الخدمة للعملاء فقط" });
    }

    await pool.query(
      "DELETE FROM cart_items WHERE id=$1 AND user_id=$2",
      [req.params.id, req.user.id]
    );

    res.json({ message: "تم حذف المنتج من السلة" });
  } catch (error) {
    res.status(500).json({ message: "حدث خطأ" });
  }
});

// =============================
// Checkout
// =============================

app.post("/api/checkout", authenticateToken, async (req, res) => {
  const client = await pool.connect();

  try {
    if (req.user.role !== "customer") {
      return res.status(403).json({ message: "هذه الخدمة للعملاء فقط" });
    }

    const { customer_phone, address } = req.body;

    if (!customer_phone || !address) {
      return res.status(400).json({ message: "أدخل رقم الهاتف والعنوان" });
    }

    await client.query("BEGIN");

    const cart = await client.query(
      `SELECT c.perfume_id, c.quantity, p.name, p.price, p.stock
       FROM cart_items c
       JOIN perfumes p ON p.id=c.perfume_id
       WHERE c.user_id=$1
       FOR UPDATE OF p`,
      [req.user.id]
    );

    if (!cart.rows.length) {
      await client.query("ROLLBACK");
      return res.status(400).json({ message: "السلة فارغة" });
    }

    for (const item of cart.rows) {
      if (item.quantity > item.stock) {
        throw new Error(`الكمية غير متوفرة للعطر: ${item.name}`);
      }
    }

    const total = cart.rows.reduce(
      (sum, item) => sum + Number(item.price) * item.quantity, 0
    );

    const order = await client.query(
      `INSERT INTO orders (user_id, total, customer_phone, address)
       VALUES ($1,$2,$3,$4) RETURNING *`,
      [req.user.id, total, customer_phone, address]
    );

    for (const item of cart.rows) {
      await client.query(
        `INSERT INTO order_items
         (order_id, perfume_id, perfume_name, price, quantity)
         VALUES ($1,$2,$3,$4,$5)`,
        [order.rows[0].id, item.perfume_id, item.name,
         item.price, item.quantity]
      );

      await client.query(
        "UPDATE perfumes SET stock=stock-$1 WHERE id=$2",
        [item.quantity, item.perfume_id]
      );
    }

    await client.query(
      "DELETE FROM cart_items WHERE user_id=$1",
      [req.user.id]
    );

    await client.query("COMMIT");

    res.status(201).json({
      message: "تم استلام طلبك بنجاح",
      order: order.rows[0]
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(error);
    res.status(400).json({
      message: error.message || "تعذر إتمام الطلب"
    });
  } finally {
    client.release();
  }
});

// =============================
// Customer Orders
// =============================

app.get("/api/orders", authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== "customer") {
      return res.status(403).json({ message: "هذه الخدمة للعملاء فقط" });
    }

    const result = await pool.query(
      `SELECT o.*,
       COALESCE(
         json_agg(
           json_build_object(
             'perfume_name', oi.perfume_name,
             'price', oi.price,
             'quantity', oi.quantity
           )
         ) FILTER (WHERE oi.id IS NOT NULL),
         '[]'
       ) AS items
       FROM orders o
       LEFT JOIN order_items oi ON oi.order_id=o.id
       WHERE o.user_id=$1
       GROUP BY o.id
       ORDER BY o.created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "تعذر تحميل الطلبات" });
  }
});

// =============================
// Admin Dashboard APIs
// =============================

// All orders
app.get("/api/admin/orders", authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT o.*, u.name AS customer_name, u.email AS customer_email
       FROM orders o
       LEFT JOIN users u ON u.id=o.user_id
       ORDER BY o.created_at DESC`
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: "تعذر تحميل الطلبات" });
  }
});

// Order details
app.get("/api/admin/orders/:id", authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT oi.* FROM order_items oi
       WHERE oi.order_id=$1`,
      [req.params.id]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: "حدث خطأ" });
  }
});

// Update order status
app.patch("/api/admin/orders/:id", authenticateToken, adminOnly, async (req, res) => {
  try {
    const allowed = ["pending", "confirmed", "processing", "shipped", "delivered", "cancelled"];
    const { status } = req.body;

    if (!allowed.includes(status)) {
      return res.status(400).json({ message: "حالة الطلب غير صحيحة" });
    }

    const result = await pool.query(
      "UPDATE orders SET status=$1 WHERE id=$2 RETURNING *",
      [status, req.params.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ message: "الطلب غير موجود" });
    }

    res.json({ message: "تم تحديث حالة الطلب", order: result.rows[0] });
  } catch (error) {
    res.status(500).json({ message: "تعذر تحديث الطلب" });
  }
});

// All customers
app.get("/api/admin/customers", authenticateToken, adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, phone, email, created_at
       FROM users WHERE role='customer'
       ORDER BY created_at DESC`
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ message: "تعذر تحميل العملاء" });
  }
});

// Dashboard statistics
app.get("/api/admin/stats", authenticateToken, adminOnly, async (req, res) => {
  try {
    const [products, orders, customers, sales] = await Promise.all([
      pool.query("SELECT COUNT(*) FROM perfumes"),
      pool.query("SELECT COUNT(*) FROM orders"),
      pool.query("SELECT COUNT(*) FROM users WHERE role='customer'"),
      pool.query("SELECT COALESCE(SUM(total),0) AS total FROM orders WHERE status <> 'cancelled'")
    ]);

    res.json({
      products: Number(products.rows[0].count),
      orders: Number(orders.rows[0].count),
      customers: Number(customers.rows[0].count),
      sales: Number(sales.rows[0].total)
    });
  } catch (error) {
    res.status(500).json({ message: "تعذر تحميل الإحصائيات" });
  }
});

// =============================
// Server
// =============================

app.use("/api", (req, res) => {
  res.status(404).json({ message: "الطلب غير موجود" });
});

app.listen(PORT, () => {
  console.log(`Golden Rose running on port ${PORT}`);
});
