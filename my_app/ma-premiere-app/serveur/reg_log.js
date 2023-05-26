const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2') ;
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
// Create a MySQL connection pool
const pool = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "ADEMEYA05102022",
    database: "users",
    insecureAuth : true
});

// Create a new Express application
const app = express();
var corsOptions = {

    origin: "http://localhost:3000"
};
app.use(cors(corsOptions));


// Use body-parser middleware to parse request bodies
app.use(bodyParser.json());

// Define a login endpoint
app.post("/api/registre",async (req, res) => {
    // Extract the username and password from the request body
    const { nom, prenom, ddn, carteEtudiant, classe, email, password } = req.body;
    const passwordcrypt = await bcrypt.hash(password, 10);

    // Query the MySQL database to check if the username and password combination exists
 pool.query('INSERT INTO registre (nom, prenom, ddn, carteEtudiant, classe, email, password) VALUES (?,?,?,?,?,?,?)', 
  [nom, prenom, ddn, carteEtudiant, classe, email, passwordcrypt], (err, results) => {
    if (err) {
        console.log("error: ", err);
        return res.status(500).json({
            success: false,
        });
    }
    console.log(results)
    return res.status(200).json({
        test: "inserted ",
    });
});
});
// Use body-parser middleware to parse request bodies
app.use(bodyParser.json());
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    //const passwordNonCrypte
    const sql = 'SELECT * FROM registre WHERE email = ?';
    await pool.query(sql, [email], (err, result) => {
       console.log(err);
        if (err) {
            res.status(500).send('Error logging in');
        }
        else if (result.length == 0) {
            res.status(401).send('Invalid email or password');

        } else {
            const user = result[0];
            console.log(bcrypt.compareSync(password, user.password))
            if (bcrypt.compareSync(password, user.password)) {
                const token = jwt.sign({ email }, 'secret-key');
                res.status(200).send({ token,user });
            } else {
                res.status(401).send('Invalid  password');
            }
        }
    })
});

// Configuration de Multer pour le téléversement d'images
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); // Spécifiez le dossier de destination pour les images téléversées
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  }
});

const upload = multer({ storage });

// Endpoint pour le téléversement d'images
app.post('/api/upload', upload.single('image'), (req, res) => {
  // Gérer l'image téléversée ici
  const image = req.file;
  // Insérer les informations de l'image dans la base de données
  const query = 'INSERT INTO images (filename, originalname, path) VALUES (?, ?, ?)';
  pool.query(query, [image.filename, image.originalname, image.path])
    .then(() => {
      res.json({ message: 'Image téléversée avec succès.' });
    })
    .catch((err) => {
      console.error('Erreur lors de l\'enregistrement de l\'image:', err);
      res.status(500).json({ error: 'Erreur lors de l\'enregistrement de l\'image' });
    });
});


const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ message: 'Access unauthorized. Missing token.' });
  }

  jwt.verify(token, 'secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Access unauthorized. Invalid token.' });
    }

    req.user = user; // Store user information in the request
    next(); // Proceed to the next request handler
  });
};

// Endpoint to retrieve file data with required authentication
app.get('/api/getFileData', authenticateToken, (req, res) => {
  let query = "SELECT * FROM images";

  pool.query(query, (err, results) => {
    if (err) {
      console.log("Error retrieving image data:", err);
      res.status(500).send({
        message: err.message || "An error occurred while retrieving image data."
      });
    } else {
      console.log("Image data retrieved successfully.");
      res.send(results);
    }
  });
});







app.get('/api/getAllUser', (req, res) => {
  let query = "SELECT * FROM registre ORDER BY id";

  pool.query(query, (err, data) => {
    if (err) {
      console.log("error: ", err);
      res.status(500).send({
        message: err.message || "Some error occurred while retrieving users."
      });
    } else {
      console.log("Liste des utilisateurs : ", data);
      res.send(data);
    }
  });
});

app.get('/api/removeUser/:id', (req, res) => {
  const userId = req.params.id;

  let query = "DELETE FROM registre WHERE id = ?";

  pool.query(query, [userId], (err, result) => {
    if (err) {
      console.log("error: ", err);
      res.status(500).send({
        message: err.message || "Some error occurred while removing the user."
      });
    } else {
      console.log("User removed successfully.");
      res.send({
        message: "User removed successfully."
      });
    }
  });
});

// Start the server
app.listen(3100, () => {
  console.log('Server started on port 3100');
});


