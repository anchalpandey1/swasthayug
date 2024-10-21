import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import path from "path";
import { compressAndSaveImage } from "../utils/imgCompress.js";

const generateAccessAndRefereshTokens = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(
            500,
            "Something went wrong while generating referesh and access token"
        );
    }
};

//user Registeration
const registerUser = asyncHandler(async (req, res) => {
  const { username, email, password ,gender,country} = req.body;

  // Validate input fields
  if ([username, email, password,gender,country].some(field => field?.trim() === "")) {
      throw new ApiError(400, "All fields are required");
  }

  // Check if the email is already in use
  const existedUser = await User.findOne({ email });
  if (existedUser) {
      throw new ApiError(409, "User with this email already exists");
  }

  let imgUrl;
  // Process the uploaded file (image or PDF)
  if (req.file) {
      if (req.file.mimetype.startsWith("image/")) {
          // Compress and save the image
          const imagePath = await compressAndSaveImage(req.file.buffer, req.file.originalname);
          imgUrl = `${path.basename(imagePath)}`;
      } else if (req.file.mimetype === "application/pdf") {
          // Save the PDF directly
          const pdfPath = await savePdf(req.file.buffer, req.file.originalname);
          imgUrl = `${path.basename(pdfPath)}`;
      } else {
          return res.status(400).send("Unsupported file type.");
      }
  }

  // Create a new user instance
  const user = new User({
      username,
      email,
      password,
      profileUrl: imgUrl || null, // Save image/PDF URL if exists
      gender,
      country,
  });

  // Save the new user to the database (password is automatically hashed due to pre-save hook)
  await user.save();

  // Select only necessary fields for the response (exclude password and refreshToken)
  const createdUser = await User.findById(user._id).select("-password -refreshToken");

  if (!createdUser) {
      throw new ApiError(500, "Something went wrong while registering the user");
  }

  // Return the response with the newly created user details
  return res
      .status(201)
      .json(new ApiResponse(200, createdUser, "User registered successfully"));
});



//user Login
const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    // console.log(email);

    if (!password && !email) {
        return res
            .status(400)
            .json(new ApiError(400, null, "password or email is required"));
    }

    const user = await User.findOne({
        $or: [{ email }],
    });
    if (!user) {
        return res
            .status(404)
            .json(new ApiError(404, null, "User does not exist"));
    }

    const isPasswordValid = await user.isPasswordCorrect(password);

    if (!isPasswordValid) {
        return res
            .status(401)
            .json(new ApiError(401, null, "Invalid user credentials"));
    }

    const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(
        user._id
    );

    const loggedInUser = await User.findById(user._id).select(
        "-password  -profileUrl   -refreshToken -createdAt -updatedAt -__v"
    );

    const options = {
        httpOnly: true,
        secure: true,
    };

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(
                200,
                loggedInUser,
                "userInfo",
                "User logged In Successfully",
                accessToken,
                refreshToken
            )
        );
});

const getCurrentUser = asyncHandler(async (req, res) => {
    // Get the authenticated user's ID from the request
    const id = req.user._id;

    // Find the user by ID
    const user = await User.findById(id).select("-password -refreshToken");

    // Check if the user exists
    if (!user) {
        return res.status(404).json(new ApiError(404, null, "User Not Found"));
    }

    // Return the user's details
    return res.status(200).json(new ApiResponse(200, user,"user", "User retrieved successfully"));
});


//logout User
const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1, // this removes the field from document
            },
        },
        {
            new: true,
        }
    );

    const options = {
        httpOnly: true,
        secure: true,
    };

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, {}, "User logged Out"));
});

//deleteuser Account
const deleteAccount = asyncHandler(async (req, res) => {
  const id = req.user._id; // Get the authenticated user's ID from the request

  // Check if the user exists
  const user = await User.findById(id);
  if (!user) {
      return res.status(404).json(new ApiError(404, null, "User Not Found"));
  }

  // Attempt to delete the user account permanently
  try {
      await User.deleteOne({ _id: id });
      return res.status(200).json(new ApiResponse(200, null, {}, "User deleted successfully"));
  } catch (error) {
      return res.status(500).json(new ApiError(500, null, "Error deleting user account"));
  }
});

const changePassword = asyncHandler(async (req, res) => {
  const { password, newpassword } = req.body; // Get current and new passwords from request body

  // Validate the inputs
  if (!password || !newpassword) {
      return res.status(400).json(new ApiError(400, null, "Current and new passwords are required"));
  }

  const id = req.user._id; // Get the authenticated user's ID

  // Find the user by ID
  const user = await User.findById(id);
  if (!user) {
      return res.status(404).json(new ApiError(404, null, "User Not Found"));
  }

  // Check if the current password is correct
  const isMatch = await user.isPasswordCorrect(password);
  if (!isMatch) {
      return res.status(401).json(new ApiError(401, null, "Current password is incorrect"));
  }

  // Update the user's password
  user.password = newpassword; // You might want to hash this before saving
  await user.save(); // Save the updated user

  return res.status(200).json(new ApiResponse(200, null, {}, "Password changed successfully"));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken =
        req.cookies.refreshToken || req.body.refreshToken;

    if (!incomingRefreshToken) {
        return res
            .status(401)
            .json(new ApiError(401, null, "unauthorized request"));
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        );

        const user = await User.findById(decodedToken?._id);

        if (!user) {
            return res
                .status(401)
                .json(new ApiError(401, null, "Invalid refresh token"));
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            return res
                .status(401)
                .json(
                    new ApiError(401, null, "Refresh token is expired or used")
                );
        }

        const options = {
            httpOnly: true,
            secure: true,
        };

        const { accessToken, newRefreshToken } =
            await generateAccessAndRefereshTokens(user._id);

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken: newRefreshToken },
                    "Access token refreshed"
                )
            );
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token");
        // return res.status(401).json(
        //     new ApiError(401, null, "Refresh token is expired or used" || "Invalid refresh token")
        // );
    }
});


const resetPassword = asyncHandler(async (req, res) => {
    const { emailOrPhone, newPassword } = req.body;
    const user = await User.findOne({
        $or: [{ email: emailOrPhone }, { phoneNo: emailOrPhone }],
    });
    // const isCorrect = await user.isPasswordCorrect(oldPassword)

    if (!user) {
        return res
            .status(400)
            .json(new ApiError(400, null, "Invalid Email write valid code"));
    }

    user.password = newPassword;

    user.otp = null;

    await user.save({ validateBeforeSave: false });

    return res
        .status(200)
        .json(new ApiResponse(200, {}, "Password changed successfully"));
});



export {
    registerUser,
    loginUser,
    getCurrentUser,
    logoutUser,
    deleteAccount,
    refreshAccessToken, 
    changePassword,
   
};
