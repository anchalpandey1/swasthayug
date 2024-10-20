// imageUtils.js
import sharp from "sharp";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

// Get the directory name from the module URL
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Function to compress and save image
export const compressAndSaveImage = async (buffer, originalName) => {
    try {
        // Define the path where the compressed image will be saved
        const filePath = path.join(
            __dirname,
            "../../public/uploads",
            `${Date.now()}-${originalName}`
        );

        // Ensure the uploads directory exists
        if (!fs.existsSync(path.dirname(filePath))) {
            fs.mkdirSync(path.dirname(filePath), { recursive: true });
        }

        // Compress the image
        await sharp(buffer)
            .resize({ width: 800 }) // Optional: Resize the image to width of 800 pixels
            .jpeg({ quality: 80 }) // Compress as JPEG with 80% quality
            .toFile(filePath); // Save the image to the specified path

        // Return the path of the saved image
        return filePath;
    } catch (error) {
        console.error("Error compressing and saving image:", error);
        throw error; // Throw error to be handled by calling function
    }
};

// Function to directly save PDF
export const savePdf = async (buffer, originalName) => {
    try {
        // Define the path where the PDF will be saved
        const filePath = path.join(
            __dirname,
            "../../public/uploads",
            `${Date.now()}-${originalName}`
        );

        // Ensure the uploads directory exists
        if (!fs.existsSync(path.dirname(filePath))) {
            fs.mkdirSync(path.dirname(filePath), { recursive: true });
        }

        // Save the PDF file
        fs.writeFileSync(filePath, buffer);

        // Return the path of the saved PDF
        return filePath;
    } catch (error) {
        console.error("Error saving PDF:", error);
        throw error; // Throw error to be handled by calling function
    }
};
