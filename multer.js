const express = require('express');
const app = express();
require('dotenv').config();
const port = process.env.PORT;
const multer = require('multer');
const path = require('path');


const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); //folder where files will be stored
    },
    filename: (req, file, cb) => {
        console.log("File metadata:", file);
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage });

//route to uplaod a single file

app.post('/uploads-image', upload.single('image'), (req, res) => {
    res.json({
        message: 'File Uploaded Successfully',
        file: req.file
    });
});


const uploadWithFilter = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png/;
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.test(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Not allowed'));
        }
    }
});

//multiple files

app.post('/upload-multiple', upload.array('images', 5), (req, res) => {
    res.json({
        message: 'Files Uploaded',
        files: req.files
    });
});

const uploadWithLimit = multer({
    storage,
    limits: { fileSize: 1 * 1024 * 1024 }
});

app.post('/upload-limit', uploadWithLimit.single('image'), (req, res) => {
    res.json({
        message: 'File Uploaded SuccessFully',
        file: req.file
    });
});


//upload different fields with multer

app.post('/upload-mixed', upload.fields([
    { name: 'ProfilePic', maxCount: 1 },
    { name: 'resume', maxCount: 1 }
]), (req, res) => {
    console.log(req.files);
    res.json({
        message: 'Files uploaded',
        files: req.files
    });
});

app.listen(port, () => console.log(`Server Running at Port : ${port}`));