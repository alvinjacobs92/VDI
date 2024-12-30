require("dotenv").config()
const sanitizeHTML = require('sanitize-html')
const jwt = require("jsonwebtoken")
const bcrypt = require("bcrypt")
const cookieParser = require('cookie-parser')
const express = require ("express")
const db = require("better-sqlite3")("ourApp.db")
const multer = require("multer")
const fs = require("fs")
const https = require("https")
const { spawn } = require ("child_process")
const fs2 = require('node:fs'); 


//estoy pensando que guardar el archivo con un nombre random esta bueno,
//pero que al descargarlo idealmente debe volver a tener el mismo nombre de antes.
//pero si le cambio el nombre al descargarlo, debo cambiarle el nombre al firmarlo.
//esto puede resultar en una medida de seguridad extra o un problema... tomemoslo como bueno?

db.pragma("journal_mode = WAL")

//data base set up starts here

const createTables = db.transaction(()=>{
    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL,
        pubKey STRING NOT NULL,
        privKey STRING NOT NULL
        )
        `
    ).run()

    db.prepare(`
        CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        createdDate TEXT,
        title STRING NOT NULL,
        body TEXT NOT NULL,
        signature STRING NOT NULL,
        authorid INTEGER,
        FOREIGN KEY (authorid) REFERENCES users(id)
        )
        `).run()
})

createTables()

//data base set up stops here

const app = express()

app.set("view engine", "ejs")
app.use(express.urlencoded({extended: false}))
app.use(express.static("public"))
app.use(cookieParser())

app.use (function (req,res,next){
    res.locals.errors =[]

//try to decode incoming cookie
try{
    const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
    req.user= decoded
} catch(err){
    req.user = false
}

res.locals.user = req.user
//console.log(req.user)
    next()
})

app.get("/",(req,res)=>{
    if(req.user){
        const postsStatement = db.prepare("SELECT * FROM posts WHERE authorid = ?")
        const posts = postsStatement.all(req.user.userid)
        return res.render("dashboard", {posts})
    }
    return res.render("homepage")
})

const upload = multer({dest: "uploads"})
const multipleUpload = upload.fields([{name: 'doc', maxCount: 1},{name: 'sig', maxCount: 1}])

app.get("/sign-document",(req,res)=>{
    res.render("sign-document")
})

app.post("/upload",upload.single("file"),(req,res)=>{

    //res.redirect("/")

    //here we need tu sign the uploaded file, then save the signature, maybe with the same reference code as the file.
    //signing has 2 inputs: the file reference code, and the privKey.
    const { spawn } = require ("child_process")

//fileRefCode = req.file.filename
//privKey deberia buscar el authorid = req.user.userid, y con el pedir la privkey
const statement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
const aux = statement.get(req.user.userid)

//Aca le paso las variables a la funcion sign
const childPython = spawn ('python3',['./python/sign.py',req.file.filename,aux.privKey])

childPython.stdout.on('data',(data)=>{
    console.log(`stdout: ${data}`);
});

//Aca valido por si hubo errores durante la ejecucion del sign.py
childPython.stderr.on('data', (data) => {
    console.log(`stderr: ${data}`);
});

childPython.on('close', (code) => {
    console.log(`child process exited with code ${code}`);
});
// end of calling python.


//the signature is being stored temorarily in the signature file in the main folder.
//it is read to the variable signature.
//signature = fs.readFileSync("./uploads/signatures/test1",'utf8');


//signature = fs.readFileSync("./uploads/signatures/test1",'utf8');
//what if i dont even need to open the signature here, I can just reference it by /uploads/signatures/{req.file.filename}




//now it is needed to store this signature. we can store it in the python code, in a different location to the main folder we are using now.


//the system uses an aux signature file for now... can be improved... by getting the output directly from sign.py... MVP excuse...

//reading signature from file
//signature = fs.readFileSync('signature','utf8')

//upload file data to post
signature=0;
const ourStatement = db.prepare("INSERT INTO posts (title,body,signature,authorid,createdDate) VALUES(?,?,?,?,?)")
const result = ourStatement.run(req.file.originalname,req.file.filename,signature,req.user.userid, new Date().toISOString())

const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?")
const realPost = getPostStatement.get(result.lastInsertRowid)

//res.send(req.file)
//res.download(req.file.path,req.file.originalname)
//console.log(req.file.path)

res.redirect(`/post/${realPost.id}`)

})

app.get("/post/:id",(req,res)=>{
    const statement = db.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?")
    const post = statement.get(req.params.id)

    if(!post){
        return res.redirect("/")
    }

    //console.log(post)

    res.render("single-post",{post})
})









app.get("/download-file/:id",(req,res)=>{
    const postsStatement = db.prepare("SELECT * FROM posts WHERE  authorid = ?")
    
    const posts = postsStatement.all(req.user.userid)
    //const posts = postsStatement.get( id del post que estoy queriendo bajar.)

    console.log(req.user.userid)
    res.download(`./uploads/${req.params.id}`);

})

app.get("/download-signature/:id",(req,res)=>{
    res.download(`./uploads/signatures/${req.params.id}`);
})










app.get("/verify-signature",(req,res)=>{
    res.render("verify-signature");
})
























app.post("/verify", multipleUpload,(req,res)=>{

    //I will receive two files and a string.
    //I need to run the verify.py script and send it a pointer to the file on storage, the signature fits as a variable (no need to store) and the pubkey as a decodified variable obtained from the received string... so first decode the string into a variable.
    //let us first receive the variables

    //cargado el archivo a la memoria, necesito su ruta.

    //codigo del documento: filename

    //placeholder


//need to send document, signature, pubkey to python.
//I will send pointers to the documents stored.

const { spawn } = require ("child_process")

//Aca le paso las variables a la funcion sign
const childPython = spawn ('python3',['./python/verify.py',req.files.doc[0].originalname,req.files.doc[0].filename,req.files.sig[0].filename,req.body.body])

childPython.stdout.on('data',(data)=>{
    console.log(`stdout: ${data}`);
    return res.render("result", {data})
});

//Aca valido por si hubo errores durante la ejecucion del sign.py
childPython.stderr.on('data', (data) => {
    console.error(`stderr: ${data}`);
});

childPython.on('close', (code) => {
    console.log(`child process exited with code ${code}`);
});


//save the file with the correct name so it verifies.


//

//redirect homepage
//res.redirect("/")
    //end of placeholder

















})











app.get("/logout", (req,res)=>{
    res.clearCookie("ourSimpleApp")
    res.redirect("/")
})

app.get("/login",(req,res)=>{
    res.render("login")
})

app.post("/login",(req,res)=>{

    let errors = []

    //checking if the input is a string
    if(typeof req.body.username !== "string") req.body.username = ""
    if(typeof req.body.password !== "string") req.body.password = ""

    //cleaning data input from spaces at begining/end
    req.body.username = req.body.username.trim()

    if(req.body.username == "string") errors =["invalid username / password"]
    if(req.body.password == "string") errors =["invalid username / password"]

    if(errors.length){
        return res.render("login",{errors})
    }

    const userInQuestionStatement = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const userInQuestion = userInQuestionStatement.get(req.body.username)

    if(!userInQuestion){
        errors =["invalid username / password"]
        return res.render("login",{errors})
    }
    const matchOrNot = bcrypt.compareSync(req.body.password, userInQuestion.password)
    if(!matchOrNot){
        errors =["invalid username / password"]
        return res.render("login",{errors})
    }else{
        //give them a cookie
        const ourTokenValue = jwt.sign({exp: Math.floor(Date.now()/1000)+60*60*24, skyColor: "blue", userid: userInQuestion.id, username: userInQuestion.username},process.env.JWTSECRET)

        res.cookie("ourSimpleApp",ourTokenValue,{
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 1000 * 60 * 60 * 24//valida por 24 horas
        })
    
        res.redirect("/")
        //redirect
    }
})

function mustBeLoggedIn(req, res, next){
    if(req.user){
        return next()
    }
    return res.redirect("/")
}

app.get("/create-post", mustBeLoggedIn, (req,res)=>{
    res.render("create-post")
})

function sharedPostValidation (req){
    const errors = []

    //spelling out rules
    if( typeof req.body.title !== "string") req.body.title = ""
    if( typeof req.body.body !== "string") req.body.title = ""

    req.body.title = sanitizeHTML(req.body.title.trim(),{allowedTags:[], allowedAttributes:{}})
    req.body.body = sanitizeHTML(req.body.body.trim(),{allowedTags:[], allowedAttributes:{}})

    if(!req.body.title) errors.push("You must provide a title")
    if(!req.body.body) errors.push("You must provide a body")

    return errors

}

app.get("/post/:id",(req,res)=>{
    const statement = db.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid = users.id WHERE posts.id = ?")
    const post = statement.get(req.params.id)

    if(!post){
        return res.redirect("/")
    }

    res.render("single-post",{post})
})

app.get("/profile", (req, res)=>{

    if(req.user){

        res.redirect(`/${req.user.username}`)
    }
    else
    res.redirecr("/")

})

app.get("/:id", (req, res) =>{
    
    if(req.user){
    const statement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const profile = statement.get(req.user.userid)
    //profile.pubKey = profile.pubKey.replace('\n', '<br/>');



    const aux = profile.pubKey.split("\n")

    profile.pubKey = aux

    console.log(profile.pubKey)
    //res.render("profile",{profile})
    res.render("profile",{profile})
    }
    else
    res.redirecr("/")
})

app.post("/create-post", mustBeLoggedIn, (req,res)=>{

    const errors = sharedPostValidation(req)

    if(errors.length){
        return res.render("create-post",{errors})
    }

        //save into database
    //const ourStatement = db.prepare("INSERT INTO posts (title,body,authorid,createdDate) VALUES(?,?,?,?)")
    //const result = ourStatement.run(req.body.title,req.body.body,req.user.userid, new Date().toISOString())

    //let pubKey;
    signature = fs.readFileSync('signature','utf8')
    console.log(signature)

    const ourStatement = db.prepare("INSERT INTO posts (title,body,signature,authorid,createdDate) VALUES(?,?,?,?,?)")
    const result = ourStatement.run(req.body.title,req.body.body,signature,req.user.userid, new Date().toISOString())

    const getPostStatement = db.prepare("SELECT * FROM posts WHERE ROWID = ?")
    const realPost = getPostStatement.get(result.lastInsertRowid)

    res.redirect(`/post/${realPost.id}`)
})

app.post("/register",(req,res)=>{

    
    const errors = []

    //checking if the input is a string
    if(typeof req.body.username !== "string") req.body.username = ""
    if(typeof req.body.password !== "string") req.body.password = ""

    //cleaning data input from spaces at begining/end
    req.body.username = req.body.username.trim()

    // checking for errors in input username
    //username rules
    if(!req.body.username) errors.push("You must provide a username")
    if(req.body.username.length < 3) errors.push("Username must be at least 3 characters.")
    if(req.body.username.length > 10) errors.push("Username must be at most 10 characters.")
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters and numbers")
    
    //check if username exists already
    const usernameStatement = db.prepare("SELECT * FROM users WHERE username = ?")
    const usernameCheck = usernameStatement.get(req.body.username)

    if(usernameCheck) errors.push("That username is already taken")

    //password rules
    if(!req.body.password) errors.push("You must provide a password")
    if(req.body.password.length < 12) errors.push("The password must be at least 12 characters.")
    if(req.body.password.length > 70) errors.push("The password must be at most 70 characters.")

    if(errors.length)
    {
        return res.render("homepage",{errors})
    } 

    //no errors if it got here.

    //need to generate privKey, pubKey pair.



//summon python script
const childPython = spawn ('python3',['./python/generate_keys.py'])

childPython.on('close', (code) => {
    console.log(`child process exited with code ${code}`);
});

//end of summon python script.

//now that new keys have been generated, I need to read them first, then add them to the database related to the new user and password.
//read pubKey

let pubKey;
pubKey = fs.readFileSync('public.pem','utf8')
console.log(pubKey)
let privKey;
privKey = fs.readFileSync('private.pem','utf8')
console.log(privKey)

//now that I have read the pubKey and privKey pair, I need to add them to the database.
//for that I will need to alter the user database, to add the new fields.
//I will also add a security level field to the database. I will also alter the names of the variables of the database later.
//new fields: privKey, pubKey, secLevel. secLevel will be added in the future.

    //save the user into a database
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password,salt)


    //const ourStatement = db.prepare("INSERT INTO users(username,password,pubKey,privKey) VALUES(?, ?, ?, ?)")
    //const result = ourStatement.run(req.body.username,req.body.password,pubKey,privKey)
    const ourStatement = db.prepare("INSERT INTO users(username,password, pubKey, privKey) VALUES(?, ?, ?, ?)")
    const result = ourStatement.run(req.body.username,req.body.password, pubKey, privKey)

    const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ourUser = lookupStatement.get(result.lastInsertRowid)

    //log the user in by giving them a cookie
    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now()/1000)+60*60*24, skyColor: "blue", userid: ourUser.id, username: ourUser.username},process.env.JWTSECRET)

    res.cookie("ourSimpleApp",ourTokenValue,{
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24//valida por 24 horas
    })

    res.redirect("/")

})


















app.listen(3000)