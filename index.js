const express = require('express');
require('dotenv').config();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { swaggerDocs } = require('./config/swagger');
const apiResponse = require('./utils/apiResponse');

const connectDB = require('./db/db.connection.js');
const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Routes
const authRoutes = require('./routes/auth.routes');
const dashboardRoutes = require('./routes/dashboard.routes');

// API Routes
app.use('/api/v1/auth', authRoutes);
app.use('/api/v1/dashboard', dashboardRoutes);

// Root route
app.get('/', (req, res) => {
  res.send('QuantrustPKI API is running');
});

app.use('/api/v1', (req, res) => {
  return apiResponse.notFound(res, `Route not found: ${req.originalUrl}`);
});

swaggerDocs(app);

const serverPort = process.env.SERVER_PORT || 9000;
app.listen(serverPort,()=>{
    console.log(`Server is running on port ${serverPort}`);
})
