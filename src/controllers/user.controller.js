import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
import { asyncHandler } from "../services/asyncHandler.js";
import { ApiError } from "../services/ApiError.js";
import { ApiResponse } from "../services/ApiResponse.js";
import { v4 as uuidv4 } from "uuid";
import mailSender from "../utils/email.js";
import { verificationTemplate } from "../utils/template/emailVerification.js";
import uploadMediaToCloudinary from "../utils/uploadToCloudinary.js";

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId).select("-password");
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();
    user.refreshToken = refreshToken;

    await user.save({ validateBeforeSave: false });

    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(
      500,
      "something went wrong while generating access and refresh token"
    );
  }
};

export const register = asyncHandler(async (req, res) => {
  const { name, userName, email, password } = req.body;
  if ([name, userName, email, password].some((field) => field?.trim === "")) {
    throw new ApiError(400, "All fields are required");
  }

  const existingUser = await User.findOne({ $or: [{ email }, { userName }] });
  if (existingUser) {
    throw new ApiError(4001, "user already exists with this email id");
  }
  const user = await User.create({ name, userName, email, password });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken -verificationToken"
  );

  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering user");
  }

  const uuidToken = uuidv4();
  createdUser.verificationToken = uuidToken;
  await createdUser.save();

  await mailSender(
    createdUser.email,
    "Verification email from Dribbble",
    verificationTemplate(
      `${process.env.CLIENT_URL}/EmailVerification/${createdUser._id}/${uuidToken}`
    )
  );
  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "user registered successfully"));
});

export const login = asyncHandler(async (req, res) => {
  //get data from req body {email,password}
  //validate
  //find the user and validate
  //password check
  //access token and refresh Token
  //send cookie

  console.log("inside", login);
  const { email, password } = req.body;

  if (!email || !password) {
    throw new ApiError(400, "email and passowrd is required");
  }

  const existingUser = await User.findOne({ email });

  if (!existingUser) {
    throw new ApiError(400, "user doesnot exist");
  }

  if (!existingUser.verified) {
    throw new ApiError(401, "First verify email to login");
  }

  const isPasswordCorrect = await existingUser.isPasswordCorrect(password);

  if (!isPasswordCorrect) {
    throw new ApiError(401, "password is incorrect");
  }

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
    existingUser._id
  );

  const loggedInUser = await User.findById(existingUser._id).select(
    "-password -refreshToken"
  );

  const access_options = {
    expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: true,
  };
  const refresh_options = {
    expires: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000),
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, access_options)
    .cookie("refreshToken", refreshToken, refresh_options)
    .json(
      new ApiResponse(
        200,
        { user: loggedInUser, accessToken, refreshToken },
        "user loggedin successfully"
      )
    );
});

export const refreshAccessToken = asyncHandler(async (req, res) => {

  const refresh_Token = req.cookies.refreshToken || req.body.refreshToken;

  const incomingRefreshToken = refresh_Token;
  if (!incomingRefreshToken) {
    throw new ApiError(401, "Nonauthorised request");
  }
  try {
    const decodeToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );
    const user = await User.findById(decodeToken._id);
    if (!user) {
      throw new ApiError(401, "invalid refresh Token");
    }
    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "RefreshToken expired");
    }
    const access_options = {
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: true,
    };
    const refresh_options = {
      expires: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: true,
    };
    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
      user._id
    );

    // console.log("access token",accessToken);
    return res
      .status(200)
      .cookie("accessToken", accessToken, access_options)
      .cookie("refreshToken", refreshToken, refresh_options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken },
          "refresh AccessToken"
        )
      );
  } catch (error) {
    throw new ApiError(401, "Invalid refresh Token");
  }
});

export const logout = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    { $unset: { refreshToken: 1 } },
    { new: true }
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"));
});

export const verification = asyncHandler(async (req, res) => {
  const { token, id } = req.body;
  if (!token || !id) {
    throw new ApiError(401, "Missing field");
  }

  const user = await User.findById(id);

  if (!user) {
    throw new ApiError(401, "something went wrong while fetching user data");
  }

  const isCorrect = user.isVerificationTokenCorrect(token);
  if (isCorrect) {
    user.verified = true;
    user.verificationToken = undefined;
    await user.save();

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(
      user._id
    );

    const verifyUser = await User.findById(user._id).select(
      "-password -refreshToken"
    );

    const access_options = {
      expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: true,
    };
    const refresh_options = {
      expires: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000),
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .cookie("accessToken", accessToken, access_options)
      .cookie("refreshToken", refreshToken, refresh_options)
      .json(
        new ApiResponse(
          200,
          { user: verifyUser, accessToken, refreshToken },
          "user verify successfully"
        )
      );
  }
  throw new ApiError(401, "Something went wrong while email verificatoion");
});

export const updateProfile = asyncHandler(async (req, res) => {
  const { location, profession } = req.body;
  const profilePicture = req.files.profilePicture;

  if (!location || !profession || !profilePicture) {
    throw new ApiError(401, "Missing field");
  }

  const userId = req.user._id;
  // console.log("userId", req.user._id);

  const existingUser = await User.findById(userId);

  if (!existingUser) {
    throw new ApiError(401, "Something went wrong while updating user details");
  }

  const upload = await uploadMediaToCloudinary(profilePicture);

  if (!upload) {
    throw new ApiError(402, "Error in uploading image");
  }

  const updateUser = await User.findByIdAndUpdate(
    userId,
    { location, avatarUrl: upload?.secure_url, profession },
    { new: true }
  );
  updateUser.password = undefined;

  return res
    .status(200)
    .json(
      new ApiResponse(200, { user: updateUser }, "profile update successfully")
    );
});
