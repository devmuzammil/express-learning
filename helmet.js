const express = require('express');
const app = express();
require('dotenv').config();
const port = process.env.PORT;
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});

app.use(limiter);

app.use(cors({
    origin: "https://localhost:5173",
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

app.use(helmet());



app.listen(port, () => console.log(`Server is Running at Port : ${port}`));