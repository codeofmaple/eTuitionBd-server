require('dotenv').config();
const express = require('express')
const cors = require('cors');
const app = express()
const PORT = process.env.PORT || 3000;

// middleware
app.use(cors());
app.use(express.json());

// firebase admin
var admin = require("firebase-admin");

var serviceAccount = require("./etuitionbd-360-firebase-admin-key.json");

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});



// mongodb database
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USERNAME}:${process.env.DB_PASSWORD}@cluster0.dwmxail.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        await client.connect(); //have to comment later
        // database and collections
        const db = client.db("eTuitionBd_db")
        const userCollection = db.collection("users")
        const tuitionCollection = db.collection("tuitions")
        const applicationCollection = db.collection("applications")
        const paymentCollection = db.collection("payments")



        await client.db("admin").command({ ping: 1 });//have to comment later
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send("eTuitionBd server is running fine!");
})

app.listen(PORT, () => {
    console.log(`server is running on port ${PORT}`)
})
