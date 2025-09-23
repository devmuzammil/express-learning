const express = require('express');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const app = express();
app.use(express.json());

// create a user

app.post('/users', async (req, res) => {
    const { email, name } = req.body;
    const user = await prisma.user.create({
        data: { email, name }
    });
    res.json(user);
});

// get all the users

app.get('/users', async (req, res) => {
    const users = await prisma.user.findMany({
        include: { post: true }
    });
    res.json(users);
});

// create a post

app.post('/post', async (req, res) => {
    const { title, content, authorId } = req.body;
    const post = await prisma.post.create({
        data: { title, content, authorId }
    });
    res.json(post);
});