require('dotenv').config();
const express = require('express')
const cors = require('cors');
const app = express()
const PORT = process.env.PORT || 3000;
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

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


// user auth middleware || firebase
const verifyFirebaseToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send({ message: "Unauthorized" });

    const token = authHeader.split(" ")[1];

    try {
        const decoded = await admin.auth().verifyIdToken(token);

        req.token_email = decoded.email;
        req.token_uid = decoded.uid;

        next();
    } catch (error) {
        console.log("verifyIdToken error:", error);
        return res.status(401).send({ message: "Unauthorized" });
    }
};


async function run() {
    try {
        await client.connect(); //have to comment later
        // database and collections
        const db = client.db("eTuitionBd_db")
        const userCollection = db.collection("users")
        const tuitionCollection = db.collection("tuitions")
        const applicationCollection = db.collection("applications")
        const paymentCollection = db.collection("payments")

        // ===== ROLE VERIFIER =====
        const createRoleVerifier = (...allowedRoles) => async (req, res, next) => {
            const user = await userCollection.findOne({ email: req.token_email });
            if (!user || !allowedRoles.includes(user.role)) {
                return res.status(403).send({ message: 'Forbidden' });
            }
            req.user = user;
            next();
        };

        // Role checkers
        const verifyAdmin = createRoleVerifier('admin');
        const verifyStudent = createRoleVerifier('student');
        const verifyTutor = createRoleVerifier('tutor');


        // Users API
        app.post('/users', async (req, res) => {
            try {
                const { name, email, photo, phone } = req.body;
                let { role } = req.body;

                if (!email) return res.status(400).json({ error: "Email is required" });

                // role safely
                if (typeof role === 'string') {
                    role = role.trim().toLowerCase();
                } else {
                    role = 'student';
                }

                const existing = await userCollection.findOne({ email: email.toLowerCase() });
                if (existing) return res.status(409).json({ error: "User already exists." });

                const userDoc = {
                    name,
                    email: email.toLowerCase(),
                    photo,
                    phone,
                    role,
                    createdAt: new Date()
                };

                const result = await userCollection.insertOne(userDoc);
                return res.status(201).json({ insertedId: result.insertedId.toString() });
            } catch (err) {
                console.error("Error saving user:", err);
                return res.status(500).json({ error: "Internal Server Error" });
            }
        });


        //  GET Single User (For Role Verification)
        app.get('/users/:email', verifyFirebaseToken, async (req, res) => {
            const email = req.params.email;
            const result = await userCollection.findOne({ email: email });
            res.send(result);
        });

        app.patch('/users/:id', verifyFirebaseToken, async (req, res) => {
            try {
                const id = req.params.id;
                const { name, photo, phone } = req.body;

                const filter = { _id: new ObjectId(id) };
                const existing = await userCollection.findOne(filter);

                if (!existing) {
                    return res.status(404).send({ message: "User not found" });
                }

                // only the same user can update their profile
                if (
                    !req.token_email ||
                    existing.email.toLowerCase() !== req.token_email.toLowerCase()
                ) {
                    return res.status(403).send({ message: "Forbidden" });
                }

                // Update MongoDB
                const updates = {
                    ...(name !== undefined && { name }),
                    ...(photo !== undefined && { photo }),
                    ...(phone !== undefined && { phone }),
                };

                await userCollection.updateOne(filter, { $set: updates });
                const updatedUser = await userCollection.findOne(filter);

                // Sync Firebase Auth
                try {
                    let uid = req.token_uid;

                    if (!uid) {
                        const userRecord = await admin.auth().getUserByEmail(existing.email);
                        uid = userRecord.uid;
                    }

                    const authUpdates = {};
                    if (name) authUpdates.displayName = name;
                    if (photo) authUpdates.photoURL = photo;

                    if (Object.keys(authUpdates).length > 0) {
                        await admin.auth().updateUser(uid, authUpdates);
                    }
                } catch (err) {
                    console.log("Firebase Auth sync failed:", err.message);
                }

                res.send({
                    message: "Profile updated",
                    updatedUser,
                });
            } catch (err) {
                res.status(500).send({ message: "Server error" });
            }
        });


        // tuitions API
        // create a tuition
        app.post('/tuitions', verifyFirebaseToken, verifyStudent, async (req, res) => {
            try {
                const newTuition = req.body;

                const tuitionDoc = {
                    title: newTuition.title,
                    studentName: newTuition.studentName,
                    studentEmail: newTuition.studentEmail,
                    subject: newTuition.subject,
                    classGrade: newTuition.classGrade,
                    salary: Number(newTuition.salary),
                    location: newTuition.location,
                    description: newTuition.description,
                    status: 'pending',
                    isBooked: false,
                    createdAt: new Date(),
                };

                const result = await tuitionCollection.insertOne(tuitionDoc);
                res.send(result);

            } catch (err) {
                console.error("Error creating tuition:", err);
                res.status(500).send({ message: "Failed to post tuition" });
            }
        });

        //=======================================================public tutor  APIs
        // ======================================== Public Tutor APIs
        // GET All Tutors (Public)
        app.get('/tutors', async (req, res) => {
            try {
                const search = req.query.search || "";
                const subject = req.query.subject || "";

                let query = { role: 'tutor' };

                if (search) {
                    query.$or = [
                        { name: { $regex: search, $options: 'i' } },
                        { email: { $regex: search, $options: 'i' } }
                    ];
                }

                const result = await userCollection.find(query).toArray();
                res.send(result);
            } catch (error) {
                console.error("Error fetching tutors:", error);
                res.status(500).send({ message: "Error fetching tutors" });
            }
        });

        // GET Single Tutor Details
        app.get('/tutors/:id', async (req, res) => {
            try {
                const id = req.params.id;
                const query = { _id: new ObjectId(id), role: 'tutor' };
                const result = await userCollection.findOne(query);
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Error fetching tutor details" });
            }
        });

        // ======================================== Public Tuition APIs
        //  GET All Approved Tuitions
        app.get('/tuitions', async (req, res) => {
            try {
                const page = parseInt(req.query.page) || 1;
                const limit = parseInt(req.query.limit) || 9;
                const search = req.query.search || "";
                const sort = req.query.sort || "createdAt";
                const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
                const classGrade = req.query.class || "";
                const subject = req.query.subject || "";
                const location = req.query.location || "";
                const minSalary = req.query.minSalary ? parseInt(req.query.minSalary) : 0;
                const maxSalary = req.query.maxSalary ? parseInt(req.query.maxSalary) : Infinity;

                // Build query
                let query = { status: 'approved' };

                // Add filters
                if (classGrade) query.classGrade = classGrade;
                if (subject) query.subject = { $regex: subject, $options: 'i' };
                if (location) query.location = { $regex: location, $options: 'i' };
                if (minSalary > 0) query.salary = { ...query.salary, $gte: minSalary };
                if (maxSalary < Infinity) query.salary = { ...query.salary, ...(query.salary ? { $lte: maxSalary } : { $lte: maxSalary }) };

                // Add search condition
                if (search) {
                    query.$or = [
                        { subject: { $regex: search, $options: 'i' } },
                        { location: { $regex: search, $options: 'i' } }
                    ];
                }

                const skip = (page - 1) * limit;

                const result = await tuitionCollection
                    .find(query)
                    .sort({ [sort]: sortOrder })
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                const total = await tuitionCollection.countDocuments(query);

                res.send({
                    tuitions: result,
                    totalPages: Math.ceil(total / limit),
                    currentPage: page,
                    totalResults: total
                });
            } catch (error) {
                console.error("Error fetching tuitions:", error);
                res.status(500).send({ message: "Error fetching tuitions" });
            }
        });

        //  GET Single Tuition Details (Public)
        app.get('/tuitions/:id', async (req, res) => {
            try {
                const id = req.params.id;
                const query = { _id: new ObjectId(id) };
                const result = await tuitionCollection.findOne(query);
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Error fetching tuition details" });
            }
        });

        // ======================================== Tutor Application APIs
        //  POST Apply for Tuition
        app.post('/applications', verifyFirebaseToken, verifyTutor, async (req, res) => {
            try {
                const application = req.body;

                // 1. Validate if tuitionId exists
                if (!application.tuitionId) {
                    return res.status(400).send({ message: "Tuition ID is required" });
                }

                // 2. ObjectId for linking
                const tuitionIdObj = new ObjectId(application.tuitionId);

                const existingApp = await applicationCollection.findOne({
                    tuitionId: tuitionIdObj,
                    tutorEmail: application.tutorEmail
                });

                if (existingApp) {
                    return res.status(400).send({ message: "You have already applied to this tuition." });
                }

                const doc = {
                    ...application,
                    tuitionId: tuitionIdObj,
                    status: 'pending',
                    createdAt: new Date()
                };

                const result = await applicationCollection.insertOne(doc);
                res.send(result);
            } catch (error) {
                console.error(error);
                res.status(500).send({ message: "Application failed" });
            }
        });

        //  GET Applications by Tutor (Merged with Tuition Data)
        // This is used for "My Applications" AND "Ongoing Tuitions" - Tutor Dashboard
        app.get('/applications/my-applications/:email', verifyFirebaseToken, verifyTutor, async (req, res) => {
            const email = req.params.email;

            try {
                const result = await applicationCollection.aggregate([
                    {
                        $match: { tutorEmail: email }
                    },
                    {
                        $lookup: {
                            from: 'tuitions',
                            localField: 'tuitionId',
                            foreignField: '_id',
                            as: 'tuitionDetails'
                        }
                    },
                    {
                        $unwind: '$tuitionDetails'
                    }
                ]).toArray();

                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Error fetching applications" });
            }
        });

        //  DELETE Application (For Tutor to cancel) - only if status is 'pending' and edit more
        app.delete('/applications/:id', verifyFirebaseToken, verifyTutor, async (req, res) => {
            const id = req.params.id;
            const result = await applicationCollection.deleteOne({ _id: new ObjectId(id) });
            res.send(result);
        });

        // ======================================== Only for students
        // Get all tuitions
        app.get('/tuitions/student/my-tuitions', verifyFirebaseToken, verifyStudent, async (req, res) => {
            try {
                let studentEmail = req.token_email;
                if (!studentEmail) {
                    return res.status(400).send({ message: 'Email not found in authentication token' });
                }

                studentEmail = studentEmail.toLowerCase();

                const tuitions = await tuitionCollection
                    .find({ studentEmail: studentEmail })
                    .sort({ createdAt: -1 })
                    .toArray();

                return res.send(tuitions);
            } catch (error) {
                console.error('Error fetching student tuitions:', error);
                return res.status(500).send({
                    message: 'Failed to fetch tuitions',
                    error: error.message
                });
            }
        });

        // UPDATE tuition
        app.put('/tuitions/:id', verifyFirebaseToken, async (req, res) => {
            const id = req.params.id;
            const body = req.body;

            const result = await tuitionCollection.updateOne(
                { _id: new ObjectId(id) },
                { $set: body }
            );

            res.send(result);
        });

        // DELETE tuition
        app.delete('/tuitions/:id', verifyFirebaseToken, async (req, res) => {
            const id = req.params.id;

            const result = await tuitionCollection.deleteOne({
                _id: new ObjectId(id),
            });

            res.send(result);
        });

        // ======================================== Manage tutors applications
        //   GET Applications for a specific tuition
        app.get('/applications/for-my-tuition/:tuitionId', verifyFirebaseToken, async (req, res) => {
            const tuitionId = req.params.tuitionId;
            const query = { tuitionId: new ObjectId(tuitionId) };

            const result = await applicationCollection.find(query).toArray();
            res.send(result);
        });

        //   PATCH Application Status
        app.patch('/applications/status/:id', verifyFirebaseToken, async (req, res) => {
            const id = req.params.id;
            const { status } = req.body;
            const filter = { _id: new ObjectId(id) };
            const updateDoc = {
                $set: { status: status }
            };
            const result = await applicationCollection.updateOne(filter, updateDoc);
            res.send(result);
        });

        // ======================================== Tutor Dashboard APIs
        // 1. GET Tutor Revenue
        app.get('/payments/tutor/:email', verifyFirebaseToken, verifyTutor, async (req, res) => {
            try {
                const email = req.params.email;
                const query = { tutorEmail: email };

                const result = await paymentCollection.find(query).sort({ date: -1 }).toArray();
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Error fetching revenue info" });
            }
        });

        // 2. PATCH Update Application
        app.patch('/applications/update-request/:id', verifyFirebaseToken, verifyTutor, async (req, res) => {
            try {
                const id = req.params.id;
                const { experience, salary, qualifications } = req.body;

                const filter = { _id: new ObjectId(id), status: 'pending' };
                const updateDoc = {
                    $set: { experience, salary, qualifications }
                };

                const result = await applicationCollection.updateOne(filter, updateDoc);

                if (result.matchedCount === 0) {
                    return res.status(400).send({ message: "Application not found or already approved/rejected." });
                }

                res.send(result);
            } catch (error) {
                res.status(500).send({ message: "Error updating application" });
            }
        });

        // =========================================payments API
        //   POST Create Payment Intent (Stripe)
        app.post('/create-payment-intent', verifyFirebaseToken, async (req, res) => {
            const { salary } = req.body;
            const amount = parseInt(salary * 100);

            const paymentIntent = await stripe.paymentIntents.create({
                amount: amount,
                currency: 'usd',
                payment_method_types: ['card']
            });

            res.send({
                clientSecret: paymentIntent.client_secret
            });
        });

        //   POST Record Payment and Update Tuition & Application Status
        app.post('/payments', verifyFirebaseToken, async (req, res) => {
            const payment = req.body;

            // 1. Saveing to Payments Collection
            const paymentResult = await paymentCollection.insertOne(payment);

            // 2. Update Tuition Status to 'booked'
            const tuitionQuery = { _id: new ObjectId(payment.tuitionId) };
            const tuitionUpdate = {
                $set: {
                    isBooked: true,
                    status: 'booked'
                }
            };
            const tuitionResult = await tuitionCollection.updateOne(tuitionQuery, tuitionUpdate);

            // 3. Update Application Status to 'approved'
            const appQuery = { _id: new ObjectId(payment.applicationId) };
            const appUpdate = {
                $set: { status: 'approved' }
            };
            const appResult = await applicationCollection.updateOne(appQuery, appUpdate);

            res.send({ paymentResult, tuitionResult, appResult });
        });

        //   GET Payment History by Student Email
        app.get('/payments/my-payments/:email', verifyFirebaseToken, async (req, res) => {
            const email = req.params.email;
            const query = { studentEmail: email };

            // Sort by newest first
            const result = await paymentCollection.find(query).sort({ date: -1 }).toArray();
            res.send(result);
        });


        // ======================================== Only admin to manage
        // ======================================= Admin manage users
        // GET all users 
        app.get('/users', verifyFirebaseToken, verifyAdmin, async (req, res) => {
            const result = await userCollection.find().toArray();
            res.send(result);
        });

        // Change User Role
        app.patch('/users/role/:id', verifyFirebaseToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { role } = req.body;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $set: {
                    role: role
                }
            }
            const result = await userCollection.updateOne(filter, updatedDoc);
            res.send(result);
        });

        // DELETE: Remove a User
        app.delete('/users/:id', verifyFirebaseToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await userCollection.deleteOne(query);
            res.send(result);
        });

        // ======================================== Admin manage tuitions
        // GET ALL Tuitions
        app.get('/tuitions/all/all', verifyFirebaseToken, verifyAdmin, async (req, res) => {
            const result = await tuitionCollection.find().sort({ createdAt: -1 }).toArray();
            res.send(result);
        });

        // PATCH: Approve/Reject Tuition
        app.patch('/tuitions/status/:id', verifyFirebaseToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { status } = req.body;
            const filter = { _id: new ObjectId(id) };
            const updatedDoc = {
                $set: {
                    status: status
                }
            }
            const result = await tuitionCollection.updateOne(filter, updatedDoc);
            res.send(result);
        });

        //======================================== Admin Stats
        // GET Admin Stats
        app.get('/admin-stats', verifyFirebaseToken, verifyAdmin, async (req, res) => {
            const users = await userCollection.estimatedDocumentCount();
            const tuitions = await tuitionCollection.estimatedDocumentCount();

            const payments = await paymentCollection.find().toArray();

            const revenue = payments.reduce((total, payment) => {
                const amount = Number(payment.amount);
                return total + (isNaN(amount) ? 0 : amount);
            }, 0);

            res.send({
                users,
                tuitions,
                orders: payments.length,
                revenue
            });
        });


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
