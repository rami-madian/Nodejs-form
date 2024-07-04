const express = require('express');
const postgres = require("postgres")
const path = require("path")
const dotenv = require('dotenv')
const bcrypt = require("bcryptjs")

dotenv.config({ path: './.env'})

const app = express();

const db = postgres({}) // will use psql environment variables


const publicDir = path.join(__dirname, './public')

app.use(express.static(publicDir))
app.use(express.urlencoded({extended: 'false'}))
app.use(express.json())

app.set('view engine', 'hbs')


app.get("/", (req, res) => {
    res.render("index")
})

app.get("/register", (req, res) => {
    res.render("register")
})

app.get("/login", (req, res) => {
    res.render("login")
})

app.get("/update", (req, res) => {
    res.render("update")
})

app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body
    let result = await db `SELECT * FROM users WHERE email = ${email}`
    if( result.length == 0 ) {
        return res.render('login', {
            message: 'User does not exist. Please register first.'
        })
    }
    let samePassword = bcrypt.compareSync(password, result[0].password)
    if (!samePassword) {
        return res.render('login', {
            message: `Wrong password.`
        })
    } else {
        return res.render('login', {
            message: `Welcome ${result[0].name}`
        })        
    } 
})

app.post("/auth/register", async (req, res) => {
    const { name, email, password, password_confirm } = req.body
    let result = await db `SELECT email FROM users WHERE email = ${email}`
    if( result.length > 0 ) {
        return res.render('register', {
            message: 'This email is already in use'
    })
    } else if(password !== password_confirm) {
            return res.render('register', {
                message: 'Password Didn\'t Match!'
            })
    }

    let hashedPassword = await bcrypt.hash(password, 8)

    console.log(hashedPassword)
    
    let user = await db `INSERT INTO users(name, email, password) values (${name}, ${email}, ${hashedPassword})`
    if(user) {
        return res.render('register', {
            message: 'User registered!' 
        })           
    } else {
        console.log(user)
    }
})

app.post("/auth/update", async (req, res) => {
    const { name, oldpassword, newpassword } = req.body
    let result = await db `SELECT * FROM users WHERE name = ${name}`
    if( result.length == 0 ) {
        return res.render('login', {
            message: 'User does not exist. Please register first.'
        })
    }
    let samePassword = bcrypt.compareSync(oldpassword, result[0].password)
    //Here the developer will make use of the malicious injected SQL data.
    let email = result[0].email
    if (!samePassword) {
        return res.render('update', {
            message: `Wrong old password.`
        })
    }
    let password = await bcrypt.hash(newpassword, 8)

    // Unsafe code
    /*
    const pg = require("pg")
    const { Client } = pg
    const client = new Client({
        user: process.env.DATABASE_USER,
        password: process.env.DATABASE_PASSWORD,
        host: process.env.DATABASE_HOST,
        port: 5432,
        database: process.env.DATABASE,
      })
    await client.connect()
    let update = await client.query(`UPDATE users set password = \'` + password + '\' where email = \'' + email)
    if (update) {
        return res.render('update', {
            message: `Password updated successfully! ${result[0].name}`
        })
    }
    await client.end()
    */
    // End
    
    let update = await db.unsafe(`UPDATE users set password = \'` + password + '\' where email = \'' + email)
     if (update) {
        return res.render('update', {
            message: `Password updated successfully! ${result[0].name}`
        })
    }

})

app.listen(8888, ()=> {
    console.log("server started on port 8888")
})
