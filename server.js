const express = require('express');
const multer = require('multer');
const mongoose = require('mongoose');
const MongoStore = require('connect-mongo'); 
const mongoURI =  process.env.MONGODB_URI;
const path = require('path');
const fs = require('fs');
const ejs = require('ejs');
const bcrypt = require('bcryptjs');
const uuid = require('uuid');
const cors = require('cors');
const session = require('express-session');
const { randomBytes } = require('crypto');
const app = express();
const PORT = 3000;
app.use(cors());
const saltRounds = 10;
app.use(express.json());
require("dotenv").config()
const GOOGLE_CLIENT_ID= process.env.GOOGLE_CLIENT_ID
const BACKEND_URL = process.env.BACKEND_URL
const { BlobServiceClient } = require("@azure/storage-blob");
 
const SAS_TOKEN = process.env.SAS_TOKEN

const blobServiceClient = new BlobServiceClient(
  `https://devrw.blob.core.windows.net/?${SAS_TOKEN}`
);
const containerName = "kaposter";

const Filter = require('bad-words');
const filter = new Filter();

function isTextAppropriate(text) {
    return !filter.isProfane(text);
}

app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
    setHeaders: (res, filePath) => {
        const fileExtension = path.extname(filePath).toLowerCase();
        const mimeTypes = {
            '.mp4': 'video/mp4',
            '.webm': 'video/webm',
            '.ogg': 'video/ogg',
        };
        const mimeType = mimeTypes[fileExtension];
        if (mimeType) {
            res.setHeader('Content-Type', mimeType);
        }
    }
}));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false }
}));


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const uploadSchema = new mongoose.Schema({
    uploader: { type: mongoose.Schema.Types.ObjectId, ref: 'Person' },
    senderName: String,
    relationship: String,
    caption: String,
    fileName: String,
    filePath: String,
    fileType: { type: String, enum: ['image', 'video'], required: true },
    likes: { type: Number, default: 0 }, 
    comments: [{ 
        commenterName: String,
        comment: String 
    }], 
    is_approved: { type: Boolean, default: false },
    is_rejected: { type: Boolean, default: false } 
});

  const Upload = mongoose.model('Upload', uploadSchema);

  const accountSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    adminPageId: { type: String, required: true }
});

const Account = mongoose.model('Account', accountSchema);

// Google OAuth callback route
app.get('/auth/google/callback', async (req, res) => {
    try {
        const authCode = req.query.code;
        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
            
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: new URLSearchParams({
                code: authCode,
                client_id: process.env.GOOGLE_CLIENT_ID,
                client_secret: process.env.GOOGLE_CLIENT_SECRET,
                redirect_uri: `${process.env.BACKEND_URL}/auth/google/callback`,
                grant_type: 'authorization_code'
            })
        });

        const tokenData = await tokenResponse.json();
        const accessToken = tokenData.access_token;

        req.session.accessToken = accessToken;

        // Fetch user profile data using the access token
        const profileResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
            headers: {
                Authorization: `Bearer ${accessToken}`
            }
        });

        const profileData = await profileResponse.json();
        console.log("profile data is ",profileData)
        console.log('User First Name:', profileData.given_name);
        console.log('User Email:', profileData.email);
        const existingAccount = await Account.findOne({ email: profileData.email });
        
        if (existingAccount) {
            console.log("existing account : ",existingAccount)
            req.session.user = { email: profileData.email, adminPageId: existingAccount.adminPageId};
            res.redirect(`/admin/${existingAccount.adminPageId}`);
        } else {
            const password = generateRandomPassword();
            const adminPageId = uuid.v4();
            const username = profileData.email.split('@')[0]; 
            // Create a New account
            const newAccount = new Account({
                email: profileData.email,
                username,
                password,
                adminPageId
            });
            
            await newAccount.save();
            req.session.user = { email: profileData.email, adminPageId: adminPageId};

            res.redirect(`/admin/${adminPageId}`);
        }
    } catch (error) {
        console.error('Error during Google OAuth callback:', error);
        res.status(500).send('Internal Server Error');
    }
    
});
//person schema
const personSchema = new mongoose.Schema({
    name: { type: String, unique: true },
    profileImage: String,
    password: String, 
    uploads: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Upload' }],
    adminPageId: { type: String },
    message: String,
    img_link: String,
    dob: Date, 
    dod: Date 
});

// Create the Person model
const Person = mongoose.model('Person', personSchema);

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });



// MongoDB setup
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.get('/auth/google', (req, res) => {
    // Redirect to Google OAuth authentication URL//
    console.log('clinet_id:',process.env.GOOGLE_CLIENT_ID);
    res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${process.env.GOOGLE_CLIENT_ID}&redirect_uri=${process.env.BACKEND_URL}/auth/google/callback&scope=profile email`);
    
});

app.get('/', (req, res) => {
    res.render('login',{ GOOGLE_AUTH: process.env.GOOGLE_AUTH });
});

// middleware/authenticate.js
function authenticateUser(req, res, next) {
    if (req.session && req.session.user) {
        next();
    } else {
        res.status(401).send('Unauthorized: Please log in to access this page.');
    }
}

module.exports = authenticateUser;


app.post('/logout', async (req, res) => {
    try {
        // Revoke Google OAuth token
        if (req.session && req.session.accessToken) {
            const accessToken = req.session.accessToken;

            // Revoke the Google OAuth token
            await fetch(`https://oauth2.googleapis.com/revoke?token=${accessToken}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            });
        }

        // Destroy the session
        req.session.destroy(err => {
            if (err) {
                console.error('Error destroying session:', err);
                res.status(500).send('Internal Server Error');
            } else {
                // Session destroyed successfully
                res.sendStatus(200);
            }
        });
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/getAdminSession', authenticateUser, (req, res) => {
    const { user } = req.session;
    res.json(user);
});

app.get('/getAdminPageId', authenticateUser, (req, res) => {
    const { adminPageId } = req.session.user;
    res.json({ adminPageId });
});

app.get('/profile/:personId', authenticateUser, async (req, res) => {
    const { personId } = req.params;

    try {
        const person = await Person.findById(personId);
        if (!person) {
            return res.status(404).send('Person not found');
        }

        // Fetch the relationship data from the Uploads collection
        const uploads = await Upload.find({ uploader: personId }).limit(1).sort({ createdAt: -1 });
        const relationship = uploads.length > 0 ? uploads[0].relationship : 'Relationship not specified';

        // Render the profile view with the person's data including personId and relationship
        res.render('profile', {
            name: person.name,
            dobToDod: `${person.dob.toLocaleDateString()} To ${person.dod.toLocaleDateString()}`,
            message: person.message,
            password: person.password,
            profileImage: person.profileImage,
            adminPageId: person.adminPageId,
            personId: personId, 
            relationship: relationship,
            BACKEND_URL: process.env.BACKEND_URL,
        });
        
    } catch (error) {
        console.error('Error fetching person data:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Route to update the password
app.put('/updatePassword/:personId', authenticateUser, async (req, res) => {
    const { personId } = req.params;
    const { password } = req.body;

    try {
        const person = await Person.findById(personId);
        if (!person) {
            return res.status(404).send('Person not found');
        }

        // Update the password
        person.password = password;
        await person.save();

        res.status(200).json({ success: true, message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

// New route to update name, message, and dobToDod
app.post('/update', authenticateUser, async (req, res) => {
    const { personId, field, value } = req.body;

    try {
        const person = await Person.findById(personId);
        if (!person) {
            return res.status(404).json({ success: false, message: 'Person not found' });
        }

        // Update the specified field
        if (field === 'name') {
            person.name = value;
        } else if (field === 'message') {
            person.message = value;
        } else if (field === 'dobToDod') {
            const [dob, dod] = value.split(' To ');
            person.dob = new Date(dob);
            person.dod = new Date(dod);
        } else {
            return res.status(400).json({ success: false, message: 'Invalid field' });
        }

        await person.save();
        res.status(200).json({ success: true, message: 'Field updated successfully' });
    } catch (error) {
        console.error('Error updating field:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});
// Function to generate a random 6-digit numeric password
function generateRandomPassword() {
    const min = 100000;
    const max = 999999;
    return String(Math.floor(Math.random() * (max - min + 1)) + min);
}
app.get('/people', authenticateUser, async (req, res) => {
    const { adminPageId } = req.query;

    try {
        const persons = await Person.find({ adminPageId });
        res.json(persons);
    } catch (error) {
        console.error('Error fetching persons:', error);
        res.status(500).json({ error: 'Failed to fetch persons' });
    }
});
// Handle GET request for /upload/:personId
app.get('/upload/:personId', authenticateUser, async (req, res) => {
    const { personId } = req.params;
    
    try {
      const user = await Person.findById(personId);
      if (!user) {
        return res.status(404).send('User not found');
      }
      res.render('uploads', { personId: user._id, name: user.name, profileImage: user.profileImage });
    } catch (err) {
      res.status(500).send('Internal Server Error');
    }
  });


// Handle POST request for authentication
app.post('/authenticate/:personId/verify', async (req, res) => {
    const { personId } = req.params;
    const { password } = req.body;

    try {
        const person = await Person.findById(personId);
        if (!person) {
            return res.status(404).send('Person not found');
        }

        // Compare the entered password with the correct password (plain text comparison for now)
        if (password === person.password) {
            // Authentication successful
            res.redirect(`/feed/${personId}`); // Redirect to /upload/personId on success
        } else {
            // Authentication failed
            res.status(401).send('Authentication failed');
        }
    } catch (error) {
        console.error('Error during authentication:', error);
        res.status(500).send('Internal Server Error');
    }
});


app.get('/landing', (req, res) => {
    res.render('landing');
});

app.post('/upload/:personId', upload.array('files'), async (req, res) => {
    const { personId } = req.params;
    const { name, caption, relationship } = req.body;
    const files = req.files;

    try {
        const user = await Person.findById(personId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        // Check text moderation
        let isRejected = !isTextAppropriate(caption);

        const uploads = [];
    const containerClient = blobServiceClient.getContainerClient(containerName);
    
    for (const file of files) {
      const blobName = `${name}/${file.originalname}`;
      const blockBlobClient = containerClient.getBlockBlobClient(blobName);
 
      console.log("File: ", file);
 
      // Check if file buffer exists
      if (file.buffer) {
        // Upload file buffer to Azure Blob Storage
        await blockBlobClient.upload(file.buffer, file.buffer.length);
        
        const fileType = file.mimetype.split("/")[0];

            const upload = new Upload({
                uploader: user._id,
                senderName: name,
                relationship,
                caption: caption,
                fileName: file.originalname,
                filePath: blockBlobClient.url,
                fileType: fileType,
                is_rejected: isRejected
            });
            uploads.push(upload.save());
        }

        user.uploads.push(...(await Promise.all(uploads)).map(upload => upload._id));
        await user.save();

        res.json({ success: true, message: 'Files uploaded successfully' });
    }} 
    catch (error) {
        console.error('Error uploading files:', error);
        res.status(500).json({ success: false, message: 'Internal Server Error' });
    }
});

// Remove the previous /authenticator/:personId route
app.get('/authenticator/:personId', async (req, res) => {
    const { personId } = req.params;
    res.render('authenticator', { personId });
});
app.get('/signup', (req, res) => {
    res.render('signup', { GOOGLE_AUTH: process.env.GOOGLE_AUTH });
});

app.get('/createPerson', (req, res) => {
    res.render('createPerson' , {adminPageId: Account.adminPageId}) ;
});

app.post('/signup', async (req, res) => {
    const { email, username, password } = req.body; 

    try {
        // Convert email and username to lowercase for case-insensitive comparison
        const emailLower = email.toLowerCase();
        const usernameLower = username.toLowerCase();

        // Check if an account with the same email or username already exists
        const existingAccount = await Account.findOne({
            $or: [
                { email: emailLower },
                { username: usernameLower }
            ]
        });

        if (existingAccount) {
            return res.status(400).json({ message: 'Account with that email or username already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        // Generate a unique adminPageId
        const adminPageId = uuid.v4();

        // Create a new account
        const newAccount = new Account({
            email: emailLower,
            username: usernameLower,
            password: hashedPassword,
            adminPageId
        });

        await newAccount.save();

        res.status(201).json({ message: 'Account created successfully' });
    } catch (error) {
        console.error('Error during signup:', error);
        res.status(500).json({ message: 'Server error' });
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const account = await Account.findOne({ email });
        if (!account) {
            return res.status(400).send('Invalid email or password');
        }

        const passwordMatch = await bcrypt.compare(password, account.password);
        if (!passwordMatch) {
            return res.status(400).send('Invalid email or password');
        }

        // Set the session data for the logged-in user
        req.session.user = { email: account.email, adminPageId: account.adminPageId };

        // Redirect to the admin page with the adminPageId
        res.redirect(`/admin/${account.adminPageId}`);
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Route to render the admin page for a specific adminPageId
app.get('/admin/:adminPageId', authenticateUser, async (req, res) => {
    const { adminPageId } = req.params;

    console.log('Accessing admin page for adminPageId:', adminPageId); // Debug log

    try {
        const account = await Account.findOne({ adminPageId });
        if (!account) {
            return res.status(404).send('Admin page not found');
        }

        res.render('admin', {
            adminUsername: account.username,
            adminEmail: account.email,
            adminPageId: adminPageId // Pass adminPageId to the template
        });
    } catch (error) {
        console.error('Error fetching admin page data:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Handle POST request to create a new person
app.post("/createPerson", authenticateUser, upload.single('profileImage'),async (req, res) => {
    console.log("body is ",req.body);
    console.log("files is ",req.file); // Contains uploaded file
    const { name, message, adminPageId, dob, dod ,profileImage} = req.body; 
    const files = req.file;  
    console.log("profileImage",files,name);
    try {
      const containerClient = blobServiceClient.getContainerClient(containerName);
      const file=files
        const blobName = `${name}/${file.originalname}`;
        const blockBlobClient = containerClient.getBlockBlobClient(blobName);
        console.log("blobname is ",blobName)
        console.log("File: ", file);

        if (file.buffer) {
          await blockBlobClient.upload(file.buffer, file.buffer.length);
            const password = generateRandomPassword();
            const parsedDOB = new Date(dob);
            const parsedDOD = new Date(dod);
            const newPerson = new Person({
              name,
              message,
              adminPageId,
              password,
              profileImage:  blockBlobClient.url, 
              dob: parsedDOB, 
              dod: parsedDOD, 
            });
        
            await newPerson.save();
        
            console.log("Person created:", newPerson); 
        }
      res.redirect(`/admin/${adminPageId}`);
    } catch (error) {
      console.error("Error creating person:", error);
      res.status(500).send("Failed to create person. Please try again later.");
    }
  });
  
// Route to render the unapproved images page for a specific user
app.get('/unapproved/:personId',authenticateUser, async (req, res) => {
  try {
    const { personId } = req.params;
    const user = await Person.findById(personId);
    if (!user) {
      return res.status(404).send('User not found');
    }
    res.render('unapproved', { personId: user._id });
  } catch (err) {
    console.error('Error rendering unapproved page:', err);
    res.status(500).send('Internal Server Error');
  }
});


// API endpoint to fetch unapproved images for a specific user
app.get('/api/unapproved-images/:personId', async (req, res) => {
    try {
        const { personId } = req.params;
        console.log("person id ",personId);
        const uploads = await Upload.find({ uploader: personId, is_approved: false, is_rejected: false  });

        const populatedUploads = await Upload.populate(uploads, { path: 'sender' });

        const images = populatedUploads.map(upload => ({
            _id: upload._id,
            url: `/uploads/${upload.senderName}/${upload.fileName}`,
            caption: upload.caption,
            link:upload.filePath,
            senderName: upload.senderName,
            relationship: upload.relationship 
        }));

        res.json({ images });
    } catch (err) {
        console.error('Error fetching unapproved images:', err);
        res.status(500).send('Internal Server Error');
    }
});
// API endpoint to fetch image URLs for a specific user
app.get('/api/image-urls/:personId', async (req, res) => {
    try {
      const { personId } = req.params;
      const uploads = await Upload.find({ uploader: personId, is_approved: false, is_rejected: false  });
      const imageUrls = uploads.map(upload => upload.filePath); // Assuming filePath contains the image URL
      res.json({ imageUrls });
    } catch (err) {
      console.error('Error fetching image URLs:', err);
      res.status(500).send('Internal Server Error');
    }
  });
// Define the endpoint to handle image approval
app.put('/approveUpload/:uploadId', authenticateUser, async (req, res) => {
    const uploadId = req.params.uploadId; // Extract uploadId from request URL

    try {
        const updatedUpload = await Upload.findByIdAndUpdate(
            uploadId,
            { $set: { is_approved: true } }, 
            { new: true } 
        );

        if (!updatedUpload) {
            return res.status(404).json({ message: 'Upload not found' });
        }

        res.json({ message: 'Upload approved successfully', upload: updatedUpload });
    } catch (error) {
        console.error('Error approving upload:', error);
        res.status(500).json({ message: 'Failed to approve upload' });
    }
});

app.get('/feed/:personId', async (req, res) => {
    const { personId } = req.params;

    try {
        const person = await Person.findById(personId);
        if (!person) {
            return res.status(404).send('Person not found');
        }
        res.render('feed', { 
            name: person.name,
            dobToDod: `${person.dob.toLocaleDateString()} To ${person.dod.toLocaleDateString()}`,
            message: person.message, 
            profileImage: person.profileImage, 
            personId: personId 
        });
    } catch (error) {
        console.error('Error fetching person data:', error);
        res.status(500).send('Internal Server Error');
    }
});



 app.get('/api/approved-images/:personId', async (req, res) => {
    const personId = req.params.personId;

    try {
        const approvedImages = await Upload.find({ uploader: personId, is_approved: true });

        res.json({ images: approvedImages });
    } catch (error) {
        console.error('Error fetching approved images:', error);
        res.status(500).json({ message: 'Failed to fetch approved images' });
    }
});

  app.delete('/deletePerson/:personId', async (req, res) => {
    const { personId } = req.params;
    try {
        await Person.findByIdAndDelete(personId);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});

// Route to remove comment
app.delete('/api/delete-comment/:imageId/:commentId', async (req, res) => {
    const { imageId, commentId } = req.params;

    try {
        const updatedImage = await Upload.findByIdAndUpdate(
            imageId,
            { $pull: { comments: { _id: commentId } } }, 
            { new: true } 
        );

        if (!updatedImage) {
            return res.status(404).json({ message: 'Image or comment not found' });
        }

        res.json({ message: 'Comment deleted successfully', image: updatedImage });
    } catch (error) {
        console.error('Error deleting comment:', error);
        res.status(500).json({ message: 'Failed to delete comment' });
    }
});
// Route 2 liking
app.post('/api/like-image/:imageId', async (req, res) => {
    const { imageId } = req.params;

    try {
        const likedImage = await Upload.findByIdAndUpdate(
            imageId,
            { $inc: { likes: 1 } },
            { new: true } 
        );

        if (!likedImage) {
            return res.status(404).json({ message: 'Image not found' });
        }
        res.json({ message: 'Image liked successfully', image: likedImage });
    } catch (error) {
        console.error('Error liking image:', error);
        res.status(500).json({ message: 'Failed to like image' });
    }
});
// Route 2 comment
app.post('/api/comment-image/:imageId', async (req, res) => {
    const { imageId } = req.params;
    const { commenterName, comment, imageIndex } = req.body; 

    try {
        const commentedImage = await Upload.findByIdAndUpdate(
            imageId,
            { $push: { comments: { commenterName, comment } } },
            { new: true } 
        );

        if (!commentedImage) {
            return res.status(404).json({ message: 'Image not found' });
        }
        res.json({ message: 'Comment added successfully', image: commentedImage, imageIndex: imageIndex, commenterName: commenterName, comment: comment });
    } catch (error) {
        console.error('Error adding comment:', error);
        res.status(500).json({ message: 'Failed to add comment' });
    }
});
// Bin i dont know the use of this, but makes sense giving an analyst is given a web development task 😂

app.get('/bin/:adminPageId', authenticateUser,async (req, res) => {
    const { adminPageId } = req.params;

    console.log('Accessing bin page for adminPageId:', adminPageId); // Debug log

    try {
        const account = await Account.findOne({ adminPageId });
        if (!account) {
            return res.status(404).send('Admin page not found');
        }

        // Fetch profiles created by the admin using the Person model
        const profiles = await Person.find({ adminPageId: adminPageId });

        // Create an array to store rejected uploads for all profiles
        const rejectedUploads = [];

        // Iterate through each profile and fetch rejected uploads
        for (const profile of profiles) {
            const uploads = await Upload.find({ uploader: profile._id, is_rejected: true });
            rejectedUploads.push(...uploads);
        }

        res.render('bin', {
            adminUsername: account.username,
            profiles: profiles,
            rejectedUploads: rejectedUploads, 
            adminPageId: adminPageId 
        });
    } catch (error) {
        console.error('Error fetching bin page data:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.post('/restore/:id', authenticateUser, async (req, res) => {
    try {
        const upload = await Upload.findById(req.params.id);
        if (!upload) {
            return res.status(404).send('Upload not found');
        }

        upload.is_rejected = false;
        await upload.save();

        res.status(200).send('Upload restored successfully');
    } catch (error) {
        console.error('Error restoring upload:', error);
        res.status(500).send('Internal Server Error');
    }
});
// Reject an image
app.put('/rejectUpload/:uploadId', async (req, res) => {
    const uploadId = req.params.uploadId;

    try {
        const updatedUpload = await Upload.findByIdAndUpdate(
            uploadId,
            { $set: { is_rejected: true } },
            { new: true }
        );

        if (!updatedUpload) {
            return res.status(404).json({ message: 'Upload not found' });
        }

        res.json({ message: 'Upload rejected successfully', upload: updatedUpload });
    } catch (error) {
        console.error('Error rejecting upload:', error);
        res.status(500).json({ message: 'Failed to reject upload' });
    }
});
// Fetch rejected images
app.get('/api/rejected-images/:personId', async (req, res) => {
    try {
        const images = await Image.find({ personId: req.params.personId, is_rejected: true });
        res.json({ images });
    } catch (err) {
        res.status(500).send(err.message);
    }
});

// Probably last
// Route to render admin profile page
app.get('/adminProfile/:adminPageId', authenticateUser, async (req, res) => {
    const { adminPageId } = req.params;

    console.log('Accessing admin page for adminPageId:', adminPageId);
    
    try {
        const account = await Account.findOne({ adminPageId }); 

        if (!account) {
            return res.status(404).send('Admin not found');
        }

        res.render('adminProfile', { 
            adminUsername: account.username,
            adminEmail: account.email,
            adminPageId: adminPageId
        });
    } catch (error) {
        console.error('Error fetching admin details:', error);
        res.status(500).send('Internal Server Error');
    }
});

// Route to handle profile update
app.post('/adminProfile/:adminPageId',authenticateUser, async (req, res) => {
    const { adminPageId } = req.params;

    console.log('Updating admin profile for adminPageId:', adminPageId);

    const { email, username, password } = req.body;

    try {
        // Find the admin account based on adminPageId
        const account = await Account.findOne({ adminPageId });

        if (!account) {
            return res.status(404).send('Admin not found');
        }

        // Update the admin's email and/or username if provided
        if (email) {
            account.email = email;
        }
        if (username) {
            account.username = username;
        }

        // Update the admin's password if provided
        if (password) {
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            account.password = hashedPassword;
        }

        // Save the updated admin account
        await account.save();

        res.status(200).json({ message: 'Admin profile updated successfully' });
    } catch (error) {
        console.error('Error updating admin profile:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
