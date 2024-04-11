import User from "../models/user.model.js";
import jwt from "jsonwebtoken";
import { ApiError } from "../services/ApiError.js";
import { asyncHandler } from "../services/asyncHandler.js";

export const auth = asyncHandler(async (req, res, next) => {
  try {
    const token =
      req.cookies?.accessToken ||
      req.body?.accessToken ||
      req?.header("Authorization")?.replace("Bearer ", "");

      // console.log(req.body)
      // console.log(token);
    if (!token) {
      throw new ApiError(401, "unauthorised token");
    }
    const decodeToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const user = await User.findById(decodeToken._id).select(
      "-password -createdAt -updatedAt"
    );
    if (!user) {
      throw new ApiError(401, "Invalid Access Token");
    }
    req.user = user;
  } catch (error) {
    throw new ApiError(403, "Invalid accessToken");
  }
  next();
});
