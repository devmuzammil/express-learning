const emailQueue = require('../queues/emailQueue.js');


emailQueue.process(async (job) => {
    const { email, username } = job.data;

    console.log(`Sending email to ${username} at email ${email}`);

    return { success: true }
});