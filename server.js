import expres, { json } from 'express';
import mongoose, { connect } from 'mongoose';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import cors from 'cors';
import admin from "firebase-admin"
import serviceAccount from './bytes-mern-firebase-adminsdk-1goza-7026ce6597.json' assert{type: "json"}
import { getAuth } from "firebase-admin/auth"
import aws from 'aws-sdk'
import 'dotenv/config'
import { populate } from 'dotenv';

// schema imports
import User from './Schema/User.js'
import Blog from './Schema/Blog.js'
import Notification from './Schema/Notification.js'
import Comment from './Schema/Comment.js'


let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,20}$/; // regex for password

let PORT = 3000;
const server = expres();
server.use(expres.json())
server.use(cors())

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
})


mongoose.connect(process.env.DB_URL, { autoIndex: true })
    .then(console.log("Connected to the DB"))

// s3 bucket setup

const s3 = new aws.S3({
    region: "ap-south-1",
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
})

// middleware for verifying the JWT
function verifyJwt(req, res, next) {

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if (token == null) {
        return res.status(401).json({ error: "No access token" });
    }

    jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Access token is invalid" });
        }

        req.user = user.id;
        next();
    });

}

const formatDataToSend = (user) => {
    const accessToken = jwt.sign({ id: user._id }, process.env.SECRET_ACCESS_KEY)
    return {
        accessToken: accessToken,
        profile_img: user.personal_info.profile_img,
        userName: user.personal_info.userName,
        fullName: user.personal_info.fullName
    }
}

const generateUploadURL = async () => {
    const date = new Date();
    const imageName = `${nanoid()}-${date.getTime()}.jpeg`;

    return await s3.getSignedUrlPromise('putObject', {
        Bucket: 'bytes-mern-blog',
        Key: imageName,
        Expires: 2000,
        ContentType: "image/jpeg"
    })
}

const generateUserName = async (email) => {
    let userName = email.split("@")[0];
    let userNameExists = await User.exists({ "personal_info.userName": userName }).then((result) => result)

    userNameExists ? userName += nanoid().substring(0, 5) : "";
    return userName;
}

// image upload route
server.get("/get-upload-url", (req, res) => {
    generateUploadURL()
        .then(url => res.status(200).json({ uploadURL: url }))
        .catch(err => {
            console.log(err.message)
            res.status(500).json({ error: err.message })
        })
})

// sign-up route
server.post("/signup", (req, res) => {
    let { fullName, email, password } = req.body;

    // frontend data validation
    if (fullName.length < 3) {
        return res.status(403).json({ "error": "Full name must be greater than three characters" });
    }
    if (!email.length) {
        return res.status(403).json({ "error": "email required" })
    }
    if (!emailRegex.test(email)) {
        return res.status(403).json({ "error": "Enter a valid email" })
    }
    if (!passwordRegex.test(password)) {
        return res.status(403).json({ "error": "Password must be 8-16 characters long, and contain at least one uppercase and special characters" })
    }

    // Password Hashing and storing personal info data
    bcrypt.hash(password, 10, async (err, hashed_pswd) => {
        let userName = await generateUserName(email);
        let user = new User({
            personal_info: {
                fullName: fullName,
                email: email,
                password: hashed_pswd,
                userName: userName
            }
        });

        // Saving the data to DB
        user.save()
            .then((data) => {
                return res.status(200).json(formatDataToSend(data));
            })
            .catch(err => {
                if (err.code == 11000) {
                    return res.status(500).json({ "error": "email already exists" })
                }
                return res.status(500).json({ "error": err.message })
            })

    })

})

// sign-in route
server.post("/signin", (req, res) => {
    let { email, password } = req.body;

    User.findOne({ "personal_info.email": email })
        .then((user) => {
            if (!user) {
                return res.status(403).json({ "error": "email not found" });
            }
            if (!user.google_auth) {
                bcrypt.compare(password, user.personal_info.password, (err, result) => {
                    if (err) {
                        return res.status(403).json({ "error": "Error occured while login please try again" })
                    }
                    if (!result) {
                        return res.status(403).json({ "error": "Incorrect Password" })
                    } else {
                        return res.status(200).json(formatDataToSend(user))
                    }
                })
            }
            else {
                return res.status(403).json({ "error": "Account was created using Google. Please try signing in Google" })
            }

            // console.log(user)

        })
        .catch(err => {
            console.log(err);
            return res.status(500).json({ "status": err.message })
        })
})

// google auth route

server.post('/google-auth', async (req, res) => {
    let { accessToken } = req.body;
    getAuth().verifyIdToken(accessToken)
        .then(async (decodedUser) => {
            let { email, name, picture } = decodedUser
            picture = picture.replace("s96-c", "s384-c")
            let user = await User.findOne({ "personal_info.email": email }).select("personal_info.fullName personal_info.userName personal_info.profile_img google_auth")
                .then((data) => {
                    return data || null;
                })
                .catch(err => {
                    return res.status(500).json({ "error": err.message })
                })

            if (user) {
                if (!user.google_auth) {
                    return res.status(403).json({ "error": "This email was signed up without google. Please use password to login." })
                }
            }
            else {
                let userName = await generateUserName(email);
                user = new User({
                    personal_info: { fullName: name, email, profile_img: picture, userName },
                    google_auth: true
                })
                await user.save()
                    .then((data) => {
                        user = data
                    })
                    .catch(err => {
                        return res.status(500).json({ "error": err.message })
                    })
            }

            return res.status(200).json(formatDataToSend(user))
        })
        .catch(err => {
            return res.status(500).json({ "error": "Failed to authenticate with google" })
        })

})

// Change password route
server.post("/change-password", verifyJwt, (req, res) => {
    let { currentPassword, newPassword } = req.body;


    if (!passwordRegex.test(newPassword)) {
        return res.status(403).json({ error: "Password must be 8-16 characters long, and contain at least one upper case and special character" })
    }

    User.findOne({ _id: req.user })
        .then((user) => {

            if (user.google_auth) {
                return res.status(403).json({ error: "Can not change password of accounts logged in with google" })
            }

            bcrypt.compare(currentPassword, user.personal_info.password, (err, result) => {
                if (err) {
                    return res.status(500).json({ error: "Some error occured while changing password. please try again later." })
                }

                if (!result) {
                    return res.status(403).json({ error: "Current password is incorrect" })
                }

                bcrypt.hash(newPassword, 10, (err, hashed_pwd) => {
                    User.findOneAndUpdate({ _id: req.user }, { "personal_info.password": hashed_pwd })
                        .then((u) => {
                            return res.status(200).json({ status: "Password Changed Successfully" })
                        })
                        .catch(err => {
                            return res.status(500).json({ error: 'Some error occured while updating password. Please try again later' })
                        })
                })
            })
        })
        .catch(err => {
            console.log(err);
            return res.status(500).json({ error: 'User not found' })
        })

})

server.post('/latest-blogs', (req, res) => {

    let { page } = req.body;

    let maxLimit = 5;
    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.userName personal_info.fullName -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title description banner activity tags publishedAt -_id")
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/all-latest-blogs-count", (req, res) => {
    Blog.countDocuments({ draft: false })
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            console.log(err);
            return res.status(500).json({ error: err.message })
        })
})

// fetching trending blogs
server.get('/trending-blogs', (req, res) => {

    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.userName personal_info.fullName -_id")
        .sort({ "activity.total_reads": -1, "activity.total_likes": -1, "publishedAt": -1 })
        .select("blog_id title publishedAt -_id")
        .limit(5)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

// returning the blogs with the tag or search input
server.post('/search-blogs', (req, res) => {
    let { tag, page, query, author, limit, exclude_blog } = req.body;

    let findQuery;

    if (tag) {
        findQuery = { tags: tag, draft: false, blog_id: { $ne: exclude_blog } };
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, "i") };
    } else if (author) {
        findQuery = { author, draft: false }
    }

    let maxLimit = limit ? limit : 2;

    Blog.find(findQuery)
        .populate("author", "personal_info.profile_img personal_info.userName personal_info.fullName -_id")
        .sort({ "publishedAt": -1 })
        .select("blog_id title description banner activity tags publishedAt -_id")
        .skip((page - 1) * maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })

})

// counting the total number of blogs with the tag or search input
server.post('/search-blogs-count', (req, res) => {
    let { tag, query, author } = req.body;
    let findQuery;

    if (tag) {
        findQuery = { tags: tag, draft: false };
    } else if (query) {
        findQuery = { draft: false, title: new RegExp(query, "i") };
    } else if (author) {
        findQuery = { author, draft: false }
    }

    Blog.countDocuments(findQuery)
        .then(count => {
            return res.status(200).json({ totalDocs: count })
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ error: err.message })
        })

})

server.post("/search-users", (req, res) => {
    let { query } = req.body;

    User.find({
        $or: [
            { "personal_info.userName": new RegExp(query, "i") },
            { "personal_info.fullName": new RegExp(query, "i") }
        ]
    })
        .limit(50)
        .select("personal_info.userName personal_info.fullName personal_info.profile_img -_id")
        .then(users => {
            // console.log(users)
            return res.status(200).json({ users })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post('/get-profile', (req, res) => {
    let { userName } = req.body;

    User.findOne({ "personal_info.userName": userName })
        .select("-personal_info.password -google_auth -updatedAt -blogs")
        .then(user => {
            return res.status(200).json(user);
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

// profile picture change route

server.post('/update-profile-img', verifyJwt, (req, res) => {
    let { url } = req.body;

    User.findOneAndUpdate({ _id: req.user }, { "personal_info.profile_img": url })
        .then(() => {
            return res.status(200).json({ profile_img: url })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

// edit profile form route
server.post("/update-profile", verifyJwt, (req, res) => {
    let { userName, bio, social_links } = req.body;
    let bioLimit = 150;

    if (userName.length < 3) {
        return res.status(403).json({ error: "Username must be at least 3 characters." })
    }
    if (bio.length > bioLimit) {
        return res.status(403).json({ error: `Bio cannot be more than ${bioLimit}` })
    }

    let socialLinksArr = Object.keys(social_links);
    try {
        for (let i = 0; i < socialLinksArr.length; i++) {
            if (social_links[socialLinksArr[i]].length) {
                let hostName = new URL(social_links[socialLinksArr[i]]).hostname;

                if (!hostName.includes(`${socialLinksArr[i]}.com`) && socialLinksArr[i] != 'website') {
                    return res.status(403).json({ error: `${socialLinksArr[i]} link is invalid` })
                }
            }
        }
    } catch (err) {
        return res.status(500).json({ error: "You must provide the full social link with https:// included" })
    }

    let updateObj = {
        "personal_info.userName": userName,
        "personal_info.bio": bio,
        "social_links": social_links
    }

    User.findOneAndUpdate({ _id: req.user }, updateObj, {
        runValidators: true
    })
        .then(() => {
            return res.status(200).json({ userName })
        })
        .catch(err => {
            if (err.code == 11000) {
                return res.status(409).json({ error: "Username is already taken" })
            }
            return res.status(500).json({ error: err.message })
        })
})



// Create new blog route
server.post('/create-blog', verifyJwt, (req, res) => {

    let authorID = req.user
    let { title, banner, content, description, tags, draft, id } = req.body;

    if (!title) {
        return res.status(403).json({ error: "You must provide a title" })
    }

    if (!draft) {
        if (!description || description.length > 200) {
            return res.status(403).json({ error: "You must provide a description in 200 characters" })
        }

        if (!banner) {
            return res.status(403).json({ error: "You must provide a blog banner" })
        }

        if (!tags.length) {
            return res.status(403).json({ error: "You must provide atleast one tag" })
        }

        if (!content.blocks.length) {
            return res.status(403).json({ error: "You must provide some blog content" })
        }
    }



    tags = tags.map(tag => tag.toLowerCase())

    let blog_id = id || title.replace(/[^a-zA-Z0-9]/g, ' ').replace(/\s+/g, "-") + nanoid();

    if (id) {

        Blog.findOneAndUpdate({ blog_id }, { title, description, content, banner, tags, draft: draft ? draft : false })
            .then(blog => {
                return res.status(200).json({ id: blog_id })
            })
            .catch(err => {
                return res.status(500).json({ error: "Failed to update" })
            })

    } else {

        let blog = new Blog({
            title, description, banner, content, tags, author: authorID, blog_id, draft: Boolean(draft)
        })

        blog.save()
            .then(blog => {
                let increamentVal = draft ? 0 : 1;
                User.findOneAndUpdate({ _id: authorID }, { $inc: { "account_info.total_posts": increamentVal }, $push: { "blogs": blog._id } })
                    .then(user => {
                        return res.status(200).json({ id: blog.blog_id })
                    })
                    .catch(err => res.status(500).json({ error: "Failed to update total number of posts" }))
            })
            .catch(err => res.status(500).json({ error: err.message }))

    }

})

server.post("/get-blog", (req, res) => {
    let { blog_id, draft, mode } = req.body;

    let increamentVal = mode != 'edit' ? 1 : 0;

    Blog.findOneAndUpdate({ blog_id: blog_id }, { $inc: { "activity.total_reads": increamentVal } })
        .populate("author", "personal_info.fullName personal_info.userName personal_info.profile_img")
        .select("title description content banner activity publishedAt blog_id tags ")
        .then(blog => {
            User.findOneAndUpdate({ "personal_info.userName": blog.author.personal_info.userName }, { $inc: { "account_info.total_reads": increamentVal } })
                .catch(err => {
                    return res.status(500).json({ error: err.message })
                })

            if (blog.draft && !draft) {
                return res.status(500).json({ error: "You cannot access draft blogs" })
            }

            return res.status(200).json({ blog })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/like-blog", verifyJwt, (req, res) => {
    let user_id = req.user;
    let { _id, isLikedByUser } = req.body;

    let incrementVal = !isLikedByUser ? 1 : -1;

    Blog.findOneAndUpdate({ _id }, { $inc: { "activity.total_likes": incrementVal } })
        .then(blog => {
            if (!isLikedByUser) {
                let like = new Notification({
                    type: "like",
                    blog: _id,
                    notification_for: blog.author,
                    user: user_id
                })
                like.save().then(notification => {
                    return res.status(200).json({ liked_by_user: true })
                })
            }
            else {
                Notification.findOneAndDelete({ user: user_id, blog: _id, type: "like" })
                    .then(data => {
                        return res.status(200).json({ liked_by_user: false })
                    })
                    .catch(err => {
                        return res.status(500).json({ error: err.message })
                    })
            }
        })
})

server.post("/isLiked-by-user", verifyJwt, (req, res) => {
    let user_id = req.user;
    let { _id } = req.body;
    Notification.exists({ user: user_id, type: "like", blog: _id })
        .then(result => {
            return res.status(200).json({ result })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})

server.post("/add-comment", verifyJwt, (req, res) => {
    let user_id = req.user;
    let { comment, _id, blog_author, replying_to } = req.body;

    if (!comment.length) {
        return res.status(403).json({ error: "Please Write something in the comment box" })
    }

    let commentObj = {
        blog_id: _id,
        blog_author,
        comment,
        commented_by: user_id
    }

    if (replying_to) {
        commentObj.parent = replying_to;
        commentObj.isReply = true
    }

    new Comment(commentObj).save()
        .then(async (commentFile) => {
            let { comment, commentedAt, children } = commentFile;

            Blog.findOneAndUpdate({ _id }, { $push: { "comments": commentFile._id }, $inc: { "activity.total_comments": 1, "activity.total_parent_comments": replying_to ? 0 : 1 }, })
                .then(blog => { console.log("New Comment created"); });

            let notificationObj = new Notification({
                type: replying_to ? "reply" : "comment",
                blog: _id,
                notification_for: blog_author,
                user: user_id,
                comment: commentFile._id
            })

            if (replying_to) {
                notificationObj.replied_on_comment = replying_to;

                await Comment.findOneAndUpdate({ _id: replying_to }, { $push: { children: commentFile._id } })
                    .then(replyingToCommentDoc => {
                        notificationObj.notification_for = replyingToCommentDoc.commented_by;
                    })

            }

            notificationObj.save().then(notification => {
                console.log("new Notification created");
            });


            return res.status(200).json({
                comment, commentedAt, _id: commentFile._id, user_id, children
            })
        })
})

server.post("/get-blog-comments", (req, res) => {
    let { blog_id, skip } = req.body;
    let maxLimit = 5;

    Comment.find({ blog_id, isReply: false })
        .populate("commented_by", "personal_info.userName personal_info.fullName personal_info.profile_img")
        .skip(skip)
        .limit(maxLimit)
        .sort({ 'commentedAt': -1 })
        .then(comment => {
            return res.status(200).json(comment);
        })
        .catch(err => {
            console.log(err.message);
            return res.status(500).json({ "error": err.message })
        })
})

server.post("/get-replies", (req, res) => {
    let { _id, skip } = req.body;
    let maxLimit = 5;

    Comment.findOne({ _id })
        .populate({
            path: "children",
            options: {
                limit: maxLimit,
                skip: skip,
                sort: { 'commentedAt': -1 }
            },
            populate: {
                path: 'commented_by',
                select: "personal_info.profile_img personal_info.fullName personal_info.userName"
            },
            select: "-blog_id -updatedAt"
        })
        .select("children")
        .then(doc => {
            return res.status(200).json({ replies: doc.children })
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })

})

const deleteComments = (_id) => {
    Comment.findOneAndDelete({ _id })
        .then(comment => {
            if (comment.parent) {
                Comment.findOneAndUpdate({ _id: comment.parent }, { $pull: { children: _id } })
                    .then(data => {
                        console.log("Comment deleted from parent");
                    })
                    .catch(err => {
                        console.log(err);
                    })
            }

            Notification.findOneAndDelete({ comment: _id })
                .then(notification => console.log('Comment notification deleted'))
            Notification.findOneAndDelete({ reply: _id })
                .then(notification => console.log('Reply notification deleted'))

            Blog.findOneAndUpdate({ _id: comment.blog_id }, { $pull: { comments: _id }, $inc: { "activity.total_comments": -1 }, "activity.total_parent_comments": comment.parent ? 0 : -1 })
                .then(blog => {
                    if (comment.children.length) {
                        comment.children.map(replies => {
                            deleteComments(replies)
                        })
                    }
                })
        })
        .catch(err => {
            console.log(err.message);
        })

}

// delete comment route
server.post("/delete-comment", verifyJwt, (req, res) => {
    let user_id = req.user;
    let { _id } = req.body;

    Comment.findOne({ _id })
        .then(comment => {
            if (user_id == comment.commented_by || user_id == comment.blog_author) {

                deleteComments(_id)

                return res.status(200).json({ status: "done" })

            } else {
                return res.status(403).json({ error: "You can not delete this comment" })
            }
        })
})

// new notification route.(checks if there is any unread notification available)
server.get("/new-notification", verifyJwt, (req, res) => {
    let user_id = req.user;

    Notification.exists({
        notification_for: user_id, seen: false, user: { $ne: user_id }
    })
        .then(result => {
            if (result) {
                return res.status(200).json({ new_notifiction_available: true })
            } else {
                return res.status(200).json({ new_notifiction_available: false })
            }
        })
        .catch(err => {
            return res.status(500).json({ error: err.message })
        })
})



server.listen(PORT, () => {
    console.log("Listening on port ->", PORT);
})
