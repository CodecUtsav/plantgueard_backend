import express from "express";
import cors from "cors";
import "dotenv/config";
import Razorpay from "razorpay";
import crypto from "crypto";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import morgan from "morgan";
import cookieParser from "cookie-parser";

const app = express();

// --- Middleware Stack ---
app.use(morgan("dev"));
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.ORIGIN_URL
      ? process.env.ORIGIN_URL.split(",")
      : "http://localhost:3000",
    credentials: true,
  }),
);
app.use(express.json());

// --- Database Connection ---
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("DB is connected"))
  .catch((error) => console.error("DB Connection Error:", error));

// --- User Model ---
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    credits: { type: Number, default: 0 },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
  },
  { timestamps: true },
);

// --- Support Model ---
const supportSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    name: { type: String, required: true },
    email: { type: String, required: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    status: {
      type: String,
      enum: ["pending", "resolved"],
      default: "pending",
    },
  },
  { timestamps: true },
);
// --- History Model ---
const historySchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    image: { type: String, required: true }, // Base64 or URL
    result: {
      disease: String,
      confidence: Number,
      description: String,
      treatment: String,
    },
    date: { type: String, default: () => new Date().toLocaleDateString() },
  },
  { timestamps: true },
);

const HistoryModel = mongoose.model("History", historySchema);

const Support = mongoose.model("Support", supportSchema);

const User = mongoose.model("User", userSchema);

// --- Auth Middlewares ---

// 1. Verify User & Token
const userAuth = async (req, res, next) => {
  const { token } = req.cookies;

  if (!token) {
    return res
      .status(401)
      .json({ success: false, message: "Not Authorized. Login Again." });
  }

  try {
    const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = tokenDecode.id;
    req.userRole = tokenDecode.role; // Extract role from token payload
    next();
  } catch (error) {
    res
      .status(401)
      .json({ success: false, message: "Session expired or invalid token" });
  }
};

// 2. Verify Admin Privileges
const adminAuth = (req, res, next) => {
  if (req.userRole !== "admin") {
    return res
      .status(403)
      .json({ success: false, message: "Access Denied. Admin only." });
  }
  next();
};

// --- Razorpay Instance ---
const razorpayInstance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// --- Auth Endpoints ---

// Register User
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "Missing Details" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role: role || "user",
    });

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      success: true,
      user: { name: user.name, email: user.email, role: user.role },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Login User
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "7d" },
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      success: true,
      user: { name: user.name, role: user.role, credits: user.credits },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Logout
app.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  });
  res.json({ success: true, message: "Logged out" });
});

// --- Razorpay Endpoints ---

// Create Payment Order
app.post("/create-order", userAuth, async (req, res) => {
  try {
    const { amount } = req.body;
    const options = {
      amount: Number(amount) * 100, // Convert to Paise
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
    };

    const order = await razorpayInstance.orders.create(options);
    res.json({ success: true, order });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// Verify Payment & Update Credits
app.post("/verify-payment", userAuth, async (req, res) => {
  try {
    const {
      razorpay_order_id,
      razorpay_payment_id,
      razorpay_signature,
      credits,
    } = req.body;
    const userId = req.userId;

    const sign = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(sign.toString())
      .digest("hex");

    if (expectedSignature === razorpay_signature) {
      const updatedUser = await User.findByIdAndUpdate(
        userId,
        { $inc: { credits: Number(credits) } },
        { new: true },
      );
      res.json({
        success: true,
        message: "Payment Successful & Credits Added",
        credits: updatedUser.credits,
      });
    } else {
      res
        .status(400)
        .json({ success: false, message: "Payment Verification Failed" });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// --- Example Admin Route ---
app.get("/admin-stats", userAuth, adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    res.json({ success: true, totalUsers });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

app.get("/api/admin/users", userAuth, adminAuth, async (req, res) => {
  try {
    const users = await User.find({}).sort({ createdAt: -1 });
    res.json({ success: true, users });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 2. Update specific user (Admin only)
app.patch("/api/admin/users/:id", userAuth, adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;
    await User.findByIdAndUpdate(id, updateData);
    res.json({ success: true, message: "User updated" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 3. Delete user (Admin only)
app.delete("/api/admin/users/:id", userAuth, adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    await User.findByIdAndDelete(id);
    res.json({ success: true, message: "User deleted" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 4. Detailed Stats (Admin only)
app.get("/api/admin/stats", userAuth, adminAuth, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const users = await User.find({});
    const totalCredits = users.reduce(
      (acc, user) => acc + (user.credits || 0),
      0,
    );

    res.json({
      success: true,
      stats: { totalUsers, totalCredits },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// --- Admin Support Endpoints ---

// 1. Get all support requests
app.get("/api/admin/support", userAuth, adminAuth, async (req, res) => {
  try {
    // Fetches all requests, newest first
    const requests = await Support.find({}).sort({ createdAt: -1 });
    res.json({ success: true, requests });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 2. Update ticket status (Resolve)
app.patch("/api/admin/support/:id", userAuth, adminAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    const updatedTicket = await Support.findByIdAndUpdate(
      id,
      { status },
      { new: true },
    );

    if (!updatedTicket) {
      return res
        .status(404)
        .json({ success: false, message: "Ticket not found" });
    }

    res.json({ success: true, message: `Ticket marked as ${status}` });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// --- Public Support Endpoint ---

app.post("/api/support/submit", userAuth, async (req, res) => {
  try {
    const { subject, message } = req.body;
    const userId = req.userId;

    // Get user details to populate the ticket
    const user = await User.findById(userId);
    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    const newTicket = await Support.create({
      userId,
      name: user.name,
      email: user.email,
      subject,
      message,
    });

    res.json({
      success: true,
      message: "Support ticket submitted successfully",
      ticket: newTicket,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 1. Get User History
app.get("/api/history", userAuth, async (req, res) => {
  try {
    const history = await HistoryModel.find({ userId: req.userId }).sort({
      createdAt: -1,
    });
    res.json({ success: true, history });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 2. Delete History Item
app.delete("/api/history/:id", userAuth, async (req, res) => {
  try {
    const { id } = req.params;
    await HistoryModel.findOneAndDelete({ _id: id, userId: req.userId });
    res.json({ success: true, message: "Record deleted" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

// 3. Get User Insights/Stats
app.get("/api/user/stats", userAuth, async (req, res) => {
  try {
    const userId = new mongoose.Types.ObjectId(req.userId);

    const totalDiagnostics = await HistoryModel.countDocuments({ userId });

    // Aggregation for Daily Activity
    const dailyDiagnostics = await HistoryModel.aggregate([
      { $match: { userId } },
      { $group: { _id: "$date", count: { $sum: 1 } } },
      { $sort: { _id: 1 } },
      { $limit: 7 },
    ]);

    // Aggregation for Disease Breakdown
    const diseaseStats = await HistoryModel.aggregate([
      { $match: { userId } },
      { $group: { _id: "$result.disease", count: { $sum: 1 } } },
    ]);

    res.json({
      success: true,
      stats: { totalDiagnostics, dailyDiagnostics, diseaseStats },
    });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`),
);
