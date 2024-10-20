import { app } from "./app.js";
import connectDB from "./database/dbConnection.js";
import http from "http";

// Create HTTP server
const httpServer = http.createServer(app);

// Connect to the database and start the HTTP server
connectDB()
    .then(() => {
        // Start HTTP server
        httpServer.listen(process.env.httpPORT || 8000, () => {
            console.log(
                `⚙️  HTTP Server is running at port : ${process.env.httpPORT}`
            );
        });
    })
    .catch((err) => {
        console.log("MONGO DB connection failed !!!", err);
    });
