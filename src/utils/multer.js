// multerConfig.js
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";

// Get the directory name from the module URL
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Define storage for Multer
const storage = multer.memoryStorage(); // Store files in memory (buffer)

// Create Multer instance
const upload = multer({
    storage: storage,
    limits: { fileSize: 50 * 1024 * 1024 }, // Limit file size to 5MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png |pdf/;
        const extname = allowedTypes.test(
            path.extname(file.originalname).toLowerCase()
        );
        const mimetype = allowedTypes.test(file.mimetype);
        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error("Only images are allowed"));
        }
    },
});

export default upload;
