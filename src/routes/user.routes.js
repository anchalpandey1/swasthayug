import { Router } from "express";
import {
    registerUser,
    loginUser,
    getCurrentUser,
    logoutUser,
    deleteAccount,
    changePassword,
   
} from "../controllers/user.controller.js";
import upload from "../utils/multer.js";
import { validateRequestBody } from "../middlewares/validation.middleware.js";

const router = Router();
import { verifyJWT } from "../middlewares/auth.middleware.js";

//Admin Related
router.route("/signup").post(upload.single("profileUrl"), registerUser);
router.route("/signin").post(loginUser);
router.route("/get").get(verifyJWT, getCurrentUser);
router.route("/logout").post(verifyJWT, logoutUser);
router.route("/deleteAccount/:id").delete(verifyJWT, deleteAccount);
router.route("/changepassword/:id").post(verifyJWT, changePassword);

export default router;
