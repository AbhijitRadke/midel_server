const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');

// Initialize Firebase Admin SDK
const serviceAccount = require('./firebase-service-account.json'); // Replace with your file
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: 'https://movement-iot-default-rtdb.firebaseio.com/' // Replace with your Firebase URL
});

// Set up Express app
const app = express();
app.use(bodyParser.json());

const PORT = 3000;

// Route to receive data from Arduino
app.get('/', async (req, res) => {


    try {

        res.status(200).send({ message: 'Server is running' });
    } catch (error) {
        console.log(error.message);
        res.status(500).send({ message: error.message });
    }
});
app.post('/data', async (req, res) => {
    const sensorData = req.body;

    console.log('Received Data:', sensorData);

    try {
        // Push data to Firebase Realtime Database
        const ref = admin.database().ref('sensor-data');
        await ref.push(sensorData);
        res.status(200).send({ message: 'Data successfully sent to Firebase', data: sensorData });
    } catch (error) {
        console.error('Error sending data to Firebase:', error);
        res.status(500).send({ message: 'Failed to send data to Firebase', error });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
