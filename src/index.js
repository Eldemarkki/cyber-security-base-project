import jwt from "jsonwebtoken"
import { readFileSync } from "node:fs"
const { JsonWebTokenError } = jwt
import bcrypt from "bcryptjs"
import { open } from "sqlite"
import sqlite3 from "sqlite3"
import fastify from "fastify"
import formParser from "@fastify/formbody"
import cookieParser from "@fastify/cookie"

const app = fastify()
app.register(cookieParser, { hook: 'onRequest' })
app.register(formParser)

const secret = process.env.JWT_SECRET;

const db = await open({
    filename: "database.db",
    driver: sqlite3.Database
});

const tableExists = (await db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='Users';"))?.name === "Users"
if (!tableExists) {
    await db.exec(`CREATE TABLE Users (
        username text,
        password_hash text,
        profile_picture_url text,
        PRIMARY KEY (username)
        )`)
}

const getAllPosts = async () => {

}

/**
 * 
 * @param {import("fastify").FastifyRequest} req 
 * @returns 
 */
const getUserFromRequest = (req) => {
    if (!req.cookies) return null

    const token = req.cookies["token"]
    if (!token) return null
    try {
        const result = jwt.verify(token, secret)

        if (!result) {
            return null
        }

        return result
    }
    catch (e) {
        if (e instanceof JsonWebTokenError) {
            if (e.message === "invalid signature") {
                return null
            }
            else {
                console.log(e)
            }
        }

        return null
    }
}

app.get("/", (req, res) => {
    const user = getUserFromRequest(req)
    if (!user) {
        res.redirect("/login")
        return
    }

    res
        .type("text/html")    
        .send(`<p>welcome, ${user.username}</p>`)
})

app.get("/register", (req, res) => {
    res
        .type("html")
        .send(readFileSync("./src/pages/register.html"))
})

app.get("/login", (req, res) => {
    res
        .type("html")
        .send(readFileSync("./src/pages/login.html"))
})

app.post("/api/register", async (req, res) => {
    /**
     * @type {unknown}
     */
    const username = req.body["username"] || ""
    /**
     * @type {unknown}
     */
    const password = req.body["password"] || ""

    if (typeof username !== "string" || typeof password !== "string") {
        res.send({
            error: "username and password must both be strings"
        })

        return
    }

    const hash = bcrypt.hashSync(password)

    await db.run("INSERT INTO Users (username, password_hash, profile_picture_url) VALUES (?,?,?)", [
        username, hash, ""
    ])

    const token = jwt.sign({ username }, secret)

    res.setCookie("token", token, {
        sameSite: "strict",
        httpOnly: true,
        path: "/",
        maxAge: 1000 * 60 * 60 * 24 // 24 hours
    })

    return res.redirect("/")
})

app.post("/api/login", async (req, res) => {
    /**
     * @type {unknown}
     */
    const username = req.body["username"] || ""
    /**
     * @type {unknown}
     */
    const password = req.body["password"] || ""

    if (typeof username !== "string" || typeof password !== "string") {
        res.send({
            error: "username and password must both be strings"
        })

        return
    }

    const matchingUser = await db.get("SELECT * FROM Users WHERE username = ?", [username])

    if (!matchingUser || !bcrypt.compareSync(password, matchingUser.password_hash)) {
        res.send({
            error: "missing user or incorrect password"
        })
    }

    const token = jwt.sign({ username }, secret)

    res.setCookie("token", token, {
        sameSite: "lax",
        path: "/",
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 // 24 hours
    })

    return res.redirect("/")
})

app.listen({
    port: 3000
})      