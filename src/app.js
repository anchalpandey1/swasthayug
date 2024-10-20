import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from "cookie-parser";
import bodyParser from "body-parser";
import session from "express-session";
import helmet from "helmet";
import sanitize from "express-mongo-sanitize";
import xss from "xss-clean";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config({
    path: "../.env",
});

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
import { logReqRes } from "./middlewares/logger.middleware.js";

app.use(
    cors({
        origin: process.env.CORS_ORIGIN || "*", 
        credentials: true, 
    })
);

app.use(express.json({ limit: process.env.EXPRESS_JSON_LIMIT }));
app.use(sanitize());
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" }));
app.use(xss());
app.use(express.urlencoded({ extended: true }));
app.use("/image", express.static(path.join(__dirname, "..", "public/uploads")));

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(logReqRes("log.txt")); // Handle Logfile Here
app.use(
    session({
        secret: process.env.ACCESS_TOKEN_SECRET, // Replace with your secret key
        resave: false,
        saveUninitialized: false,
    })
);

app.get("/", function (req, res) {
    res.redirect("/api/v1/");
});
app.get("/api/v1/", (req, res) => {
    res.status(200).json({
        message: "Welcome to the Node.js server!",
    });
});


// Routing Statrt From Here
import userRouter from "./routes/user.routes.js";

app.use(logReqRes("log.txt"));


app.use("/api/v1/users", userRouter);


app.use((err, req, res, next) => {
    if (err.type === "entity.too.large") {
        // Error type for payload too large
        res.status(413).json({
            message: "Payload Too Large. The request size exceeds the limit.",
        });
    } else {
        next(err); 
    }
});

app.use("*", (req, res) => {
    res.status(404).send("<h1>404! Page not found</h1>");
});

export { app };
