// import fs from "fs"

// export function logReqRes(filename){
//   return (req,res,next)=>{
//     fs.appendFile(
//       filename,
//       `\n${new Date().toLocaleString()}:${req.ip} ${req.method}: ${req.path} ${JSON.stringify(req.body)} \n`,
//       (err,data)=>{
//         next();
//       }
//     );
//   };
// }

// import fs from 'fs';
// import path from 'path';
// import { fileURLToPath } from 'url';

// // Get the current directory path
// const __filename = fileURLToPath(import.meta.url);
// const __dirname = path.dirname(__filename);

// export function logReqRes() {
//   return (req, res, next) => {
//     // Determine the log filename based on the request method
//     let logFilename;
//     switch (req.method) {
//       case 'POST':
//         logFilename = 'post_requests.log';
//         break;
//       case 'PUT':
//       case 'PATCH':
//         logFilename = 'update_requests.log';
//         break;
//       case 'DELETE':
//         logFilename = 'delete_requests.log';
//         break;
//       default:
//         // Skip logging for methods other than POST, PUT/PATCH, DELETE
//         return next();
//     }

//     // Ensure log directory exists
//     const logDir = path.resolve('logs');
//     if (!fs.existsSync(logDir)) {
//       fs.mkdirSync(logDir);
//     }
// console.log(logDir);
//     // Write log entry
//     fs.appendFile(
//       path.join(logDir, logFilename),
//       `\n${new Date().toLocaleString()}: ${req.ip} ${req.method}: ${req.path} ${JSON.stringify(req.body)} \n`,
//       (err) => {
//         if (err) {
//           console.error('Error writing to log file:', err);
//         }
//         next();
//       }
//     );
//   };
// }

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

// Get the current directory path
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function logReqRes() {
    return (req, res, next) => {
        // Determine the log filename based on the request method
        let logFilename;
        switch (req.method) {
            case "POST":
                logFilename = "post_requests.log";
                break;
            case "GET":
                logFilename = "get_requests.log";
                break;
            case "PUT":
            case "PATCH":
                logFilename = "update_requests.log";
                break;
            case "DELETE":
                logFilename = "delete_requests.log";
                break;
            default:
                // Skip logging for methods other than POST, PUT/PATCH, DELETE
                return next();
        }

        // Store the original `end` method
        const originalEnd = res.end;

        // Capture the response status and body
        let responseBody = "";
        res.end = function (chunk, encoding, callback) {
            if (chunk) {
                responseBody += chunk;
            }

            let parsedBody;
            try {
                parsedBody = JSON.parse(responseBody);
            } catch (err) {
                parsedBody = {};
            }
            // Log the request and response
            const logEntry = `\n${new Date().toLocaleString()}: ${req.ip} ${req.method} ${req.path} ${JSON.stringify(req.body)} => ${res.statusCode}  ${parsedBody.message || "No message"} \n`;

            // Ensure log directory exists
            const logDir = path.resolve("logs");
            if (!fs.existsSync(logDir)) {
                fs.mkdirSync(logDir);
            }

            // Write log entry
            fs.appendFile(path.join(logDir, logFilename), logEntry, (err) => {
                if (err) {
                    console.error("Error writing to log file:", err);
                }
            });

            // Call the original `end` method
            originalEnd.call(this, chunk, encoding, callback);
        };

        next();
    };
}
