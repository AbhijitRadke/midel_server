const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');

// Decode and parse the Firebase service account key from environment variable
const serviceAccountKeyBase64 = process.env.FIREBASE_SERVICE_ACCOUNT_KEY; // Make sure this is set in Render's environment variables
if (!serviceAccountKeyBase64) {
    console.error('FIREBASE_SERVICE_ACCOUNT_KEY environment variable is missing.');
    process.exit(1); // Exit if the key is not found
}

const serviceAccount = JSON.parse(Buffer.from(serviceAccountKeyBase64, 'base64').toString('utf8'));

// Initialize Firebase Admin SDK
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: 'https://movement-iot-default-rtdb.firebaseio.com/' // Replace with your Firebase URL
});

// Set up Express app
const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000; // Use the PORT environment variable if available

app.get('/', async (req, res) => {
    try {
        res.status(200).send({ message: 'Server is running' });
    } catch (error) {
        console.log(error.message);
        res.status(500).send({ message: error.message });
    }
});
// Route to receive data from Arduino
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
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
});
