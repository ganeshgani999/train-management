import express from 'express'
import mysql from 'mysql2';
import cors from "cors"
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
app.listen('3000');
app.get('/', (req, res) => {
    res.send("Hello Server Stared on port");
})



const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "123456",
    database: "irctcdatabase",

})

app.use(express.json());
app.use(cors());

app.get("/trains", (req, res) => {
    const q = "SELECT * FROM train";
    db.query(q, (err, data) => {
        if(err) {
            return res.json(err);
        } else {
            return res.json(data);
        }
    })
})

app.post("/trains", (req, res) => {
    const q = "INSERT INTO train (`idtrain`, `trainname`, `trainstarts`, `trainends`, `traintotalseats`) VALUES (?)";
    const values = [
        22347,
        "Kadapa Express",
        "Kadapa",
        "Hyderabad",
        700,
    ];

    db.query(q, [values], (err, data) => {
        if (err) {
            return res.json(err);
        } else {
            return res.json("Train Created Successfully");
        }
    })
})

app.post("/book-seat", (req, res) => {
    const { idtrain } = req.body;

    const getTrainQuery = "SELECT * FROM train WHERE idtrain = ?";
    db.query(getTrainQuery, [idtrain], (err, data) => {
        if (err) {
            return res.json(err);
        } else if (data.length === 0) {
            return res.status(404).json("Train not found");
        } else {
            const train = data[0];
            if (train.traintotalseats > 0) {
                const updateSeatsQuery = "UPDATE train SET traintotalseats = ? WHERE idtrain = ?";
                const newSeats = train.traintotalseats - 1;
                db.query(updateSeatsQuery, [newSeats, idtrain], (err, data) => {
                    if (err) {
                        return res.json(err);
                    } else {
                        return res.json({
                            message: "Seat booked successfully",
                            trainNumber: train.idtrain,
                            trainStarts: train.trainstarts,
                            trainEnds: train.trainends,
                            totalSeatsAvailable: newSeats,
                        });
                    }
                });
            } else {
                return res.status(400).json("No seats available");
            }
        }
    });
});

const JWT_SECRET = 'your_jwt_secret_key';


app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const q = 'INSERT INTO users (username, password) VALUES (?, ?)';
        db.query(q, [username, hashedPassword], (err, result) => {
            if (err) {
                return res.status(500).json({ error: err.message });
            }
            res.status(201).json({ message: 'User registered successfully' });
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


app.post('/login', (req, res) => {
    const { username, password } = req.body;

    const q = 'SELECT * FROM users WHERE username = ?';
    db.query(q, [username], async (err, results) => {
        if (err) {
            return res.status(500).json({ error: err.message });
        }

        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const user = results[0];

        try {
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
                expiresIn: '1h'
            });

            res.json({ token });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
});

const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (token == null) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
};


app.get('/profile', authenticateToken, (req, res) => {
    res.json({ message: `Welcome ${req.user.username}`, user: req.user });
});

app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
  
    // Check if user already exists
    const checkUserQuery = "SELECT * FROM users WHERE username = ?";
    db.query(checkUserQuery, [username], async (err, data) => {
      if (err) {
        return res.status(500).json(err);
      } else if (data.length > 0) {
        return res.status(400).json("User already exists");
      } else {
        // Hash the password and store it in the database
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const insertUserQuery = "INSERT INTO users (username, password) VALUES (?, ?)";
        db.query(insertUserQuery, [username, hashedPassword], (err, result) => {
          if (err) {
            return res.status(500).json(err);
          } else {
            return res.status(201).json("User registered successfully");
          }
        });
      }
    });
  });
  


