const express = require("express");
const path = require("path");
const sqlite3 = require("sqlite3");
const { open } = require("sqlite");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const { Server } = require("socket.io");
const http = require("http");

const app = express();
app.use(express.json());
app.use(cors());

const dbPath = path.join(__dirname, "usersData.db");
let db = null;

const SECRET_KEY = "MY_SECRET_KEY";

const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"],
  },
});

const users = {};

io.on("connection", (socket) => {
  socket.on("user_connected", (username) => {
    users[username] = socket.id;
    console.log(`${username} connected`);
  });

  socket.on("private_message", (message) => {
    const receiverSocketId = users[message.receiver];
    if (receiverSocketId) {
      io.to(receiverSocketId).emit("receive_private_message", message);
    }
  });

  socket.on("join_room", (roomId) => {
    socket.join(`room_${roomId}`);
    console.log(`User ${socket.id} joined room ${roomId}`);
  });

  socket.on("public_message", (data) => {
    const { roomId, sender, content, timestamp } = data;
    io.to(`room_${roomId}`).emit("receive_public_message", {
      sender,
      content,
      timestamp,
    });
  });

  socket.on("disconnect", () => {
    for (let [username, id] of Object.entries(users)) {
      if (id === socket.id) {
        delete users[username];
        break;
      }
    }
  });
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Initialize DB and start server
const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    server.listen(3000, () => {
      console.log("Server and WebSocket running on http://localhost:3000");
    });
  } catch (error) {
    console.error(`DB Error: ${error.message}`);
    process.exit(1);
  }
};
initializeDBAndServer();

//  Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const userExists = await db.get(`SELECT * FROM users WHERE username = ?`, [
    username,
  ]);

  if (userExists) {
    return res.status(400).json({ error: "User already exists" });
  }

  await db.run(`INSERT INTO users (username, password) VALUES (?, ?)`, [
    username,
    hashedPassword,
  ]);
  res.status(200).json({ message: "User registered successfully" });
});

//  Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await db.get(`SELECT * FROM users WHERE username = ?`, [
    username,
  ]);

  if (!user) return res.status(400).json({ error: "Invalid user" });

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(400).json({ error: "Invalid password" });

  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: "30d" });
  res.status(200).json({ jwtToken: token });
});

//  Create Room
app.post("/my-rooms", authenticateToken, async (req, res) => {
  const { name, type, memberUsernames } = req.body;
  const creatorUsername = req.user.username;

  try {
    const creator = await db.get(
      `SELECT rowid AS id FROM users WHERE username = ?`,
      [creatorUsername]
    );
    if (!creator) return res.status(404).json({ error: "Creator not found" });

    const result = await db.run(
      `INSERT INTO rooms (name, creator_id, created_at, type) VALUES (?, ?, datetime('now'), ?)`,
      [name, creator.id, type]
    );

    const roomId = result.lastID;
    const allUsernames = [...new Set([...memberUsernames, creatorUsername])];

    for (const username of allUsernames) {
      const user = await db.get(
        `SELECT rowid AS id FROM users WHERE username = ?`,
        [username]
      );
      if (user) {
        await db.run(
          `INSERT INTO room_members (room_id, user_id) VALUES (?, ?)`,
          [roomId, user.id]
        );
      }
    }

    res.status(200).json({ message: "Room created", roomId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create room" });
  }
});

//  Get Public Rooms for Logged-in User
app.get("/my-rooms", authenticateToken, async (req, res) => {
  const username = req.user.username;

  try {
    const user = await db.get(
      `SELECT rowid AS id FROM users WHERE username = ?`,
      [username]
    );
    if (!user) return res.status(404).json({ error: "User not found" });

    const rooms = await db.all(`
  SELECT * FROM rooms
  WHERE type = 'public'
`);

    res.status(200).json(rooms);
  } catch (err) {
    console.error("Fetch rooms error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

//  Get All Users
app.get("/users", async (req, res) => {
  const users = await db.all(`SELECT username FROM users`);
  res.status(200).json(users);
});

//  Save Private Message
app.post("/messages", async (req, res) => {
  const { sender, receiver, content, timestamp } = req.body;
  try {
    await db.run(
      `INSERT INTO messages (sender, receiver, content, timestamp) VALUES (?, ?, ?, ?)`,
      [sender, receiver, content, timestamp]
    );
    res.status(200).json({ message: "Message saved" });
  } catch {
    res.status(500).json({ error: "Failed to save message" });
  }
});

//  Get Private Chat History
app.get("/messages/:user1/:user2", async (req, res) => {
  const { user1, user2 } = req.params;
  const messages = await db.all(
    `
    SELECT * FROM messages
    WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
    ORDER BY timestamp ASC
  `,
    [user1, user2, user2, user1]
  );

  res.status(200).json(messages);
});

//  Save Group Message
app.post("/rooms/:roomId/messages", async (req, res) => {
  const { roomId } = req.params;
  const { sender, content, timestamp } = req.body;

  await db.run(
    `INSERT INTO room_messages (room_id, sender, content, timestamp) VALUES (?, ?, ?, ?)`,
    [roomId, sender, content, timestamp]
  );

  res.json({ message: "Message saved" });
});

// Get Room Chat History
app.get("/rooms/:roomId/messages", async (req, res) => {
  const { roomId } = req.params;
  const messages = await db.all(
    `SELECT * FROM room_messages WHERE room_id = ? ORDER BY timestamp ASC`,
    [roomId]
  );
  res.json(messages);
});
