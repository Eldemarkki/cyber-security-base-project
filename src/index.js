import jwt from "jsonwebtoken"
import { readFileSync } from "node:fs"
const { JsonWebTokenError } = jwt
import bcrypt from "bcryptjs"
import { open } from "sqlite"
import sqlite3 from "sqlite3"
import fastify from "fastify"
import formParser from "@fastify/formbody"
import cookieParser from "@fastify/cookie"
import PDFDocument from "pdfkit"
import emailCheck from "node-email-check"

const app = fastify()
app.register(cookieParser, { hook: 'onRequest' })
app.register(formParser)

const db = await open({
    filename: "database.db",
    driver: sqlite3.Database
});

const tableExists = (await db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='Users';"))?.name === "Users"
if (!tableExists) {
    await db.exec(`CREATE TABLE Users (
        email text,
        password_hash text,
        profile_picture_url text,
        PRIMARY KEY (email)
    )`)

    await db.exec(`CREATE TABLE Posts (
        id integer primary key,
        content text,
        user text,
        FOREIGN KEY(user) REFERENCES Users(email)
    )`)
}

const getAllPosts = async () => {
    /**
     * @type {Array<{ 
     *   id: number, 
     *   content: string, 
     *   user: string,
     *   profile_picture_url: string
     * }>}
     */
    const result = await db.all("SELECT * FROM Posts LEFT JOIN Users ON Posts.user = Users.email")
    for (const post of result) {
        delete post.password_hash
        delete post.email
    }

    return result
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
        const result = jwt.verify(token, null, {
            algorithms: ["none"],
        })

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

app.get("/", async (req, res) => {
    const user = getUserFromRequest(req)
    if (!user) {
        res.redirect("/login")
        return
    }

    const template = readFileSync("./src/pages/index.html").toString()
    const posts = await getAllPosts()

    const postsHtml = `
        <ol>
            ${posts.map(p => {
        if (p.user === user.email) {
            return `
            <li>
                <div>
                    ${p.content} (by ${p.user})
                </div>
                <div>
                    <form action="/api/posts/${p.id}/delete" method="post">
                        <input type="submit" value="Delete" />
                    </form>
                </div>
            </li>`
        }
        else {

            return `
                    <li>
                    ${p.content} (by ${p.user})
                    </li>`
        }
    }).join("")}
        </ol>
    `

    res
        .type("text/html")
        .send(template
            .replace("%ALL_POSTS%", postsHtml)
            .replace("%EMAIL%", user.email)
        )
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
    const email = req.body["email"] || ""
    /**
     * @type {unknown}
     */
    const password = req.body["password"] || ""
    /**
     * @type {unknown}
     */
    const profilePictureUrl = req.body["profile_picture_url"] || ""

    if (typeof email !== "string" || typeof password !== "string" || typeof profilePictureUrl !== "string") {
        res.send({
            error: "email and password must both be strings"
        })

        return
    }

    const isValid = emailCheck.isValidSync(email)
    if (!isValid) {
        res.send({
            error: "email must be a valid email address"
        })
        return
    }

    const hash = bcrypt.hashSync(password)

    await db.run("INSERT INTO Users (email, password_hash, profile_picture_url) VALUES (?,?,?)", [
        email, hash, profilePictureUrl
    ])

    const token = jwt.sign({ email }, null, { algorithm: "none" })

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
    const email = req.body["email"] || ""
    /**
     * @type {unknown}
     */
    const password = req.body["password"] || ""

    if (typeof email !== "string" || typeof password !== "string") {
        res.send({
            error: "email and password must both be strings"
        })

        return
    }

    const matchingUser = await db.get("SELECT * FROM Users WHERE email = ?", [email])

    if (!matchingUser || !bcrypt.compareSync(password, matchingUser.password_hash)) {
        res.send({
            error: "missing user or incorrect password"
        })
    }

    const token = jwt.sign({ email }, null, { algorithm: "none" })
    res.setCookie("token", token, {
        sameSite: "lax",
        path: "/",
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 // 24 hours
    })

    return res.redirect("/")
})

app.post("/api/posts", async (req, res) => {
    const content = req.body.content || ""
    if (typeof content !== "string") {
        res.status(400).send({ error: "content must be a string" })
    }

    const user = getUserFromRequest(req);

    await db.run("INSERT INTO Posts (content, user) VALUES (?, ?)", [content, user.email])

    res.redirect("/")
})

app.post("/api/posts/:postId/delete", async (req, res) => {
    const user = getUserFromRequest(req)
    if (!user) {
        res.status(401).send({ error: "you must be logged in to delete a post" })
        return
    }

    const postId = req.params.postId

    await db.run("DELETE FROM Posts WHERE id = ?", [postId])

    res.redirect("/")
})

app.get("/api/posts/export", async (req, res) => {
    const doc = new PDFDocument();

    doc.fontSize(18)
    doc.text('All posts', 50, 100);

    doc.fontSize(12)
    const posts = await getAllPosts();
    posts.forEach((post, i) => {
        doc.image(post.profile_picture_url, 50, i * 30 + 130, {
            height: 20,
            width: 20,
        })
        doc.text(post.user + ": " + post.content, 80, i * 30 + 135)
    })

    doc.end();

    await res.send(doc)
})

app.listen({
    port: 3000
})      